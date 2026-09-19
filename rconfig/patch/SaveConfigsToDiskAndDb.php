<?php

namespace App\CustomClasses;

use App\Models\Category;
use App\Models\Command;
use App\Models\Config;
use App\Services\Config\FileOperations;
use App\Services\ConfigCompare\ConfigCompareExclusionCleaner;
use App\Services\ConfigHistory\ConfigHistoryManager;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Log;

/**
 * Override de App\CustomClasses\SaveConfigsToDiskAndDb (rConfig V8 Core).
 *
 * Adiciona o comportamento "Keep Unchanged Config" (tipo Oxidized): quando o
 * conteudo baixado — apos as exclusoes de diff — for identico ao ultimo config,
 * NAO grava novo arquivo nem novo registro em `configs`. Assim o historico so
 * cresce quando a config do device realmente muda.
 *
 * Controlado por RCONFIG_KEEP_UNCHANGED (env do container; default true).
 * Lido via getenv() porque o container roda `php artisan config:cache`.
 *
 * Base: core-8.2.17. Revalidar este arquivo a cada update da imagem (o upstream
 * pode mudar a classe SaveConfigsToDiskAndDb).
 */
class SaveConfigsToDiskAndDb
{
    public $configsArray;
    public $type;
    public $commandName;
    public $devicerecord;
    public $report_id;
    public $model;
    public $command;
    public $latest_version;

    public function __construct($type, $commandName, $configsArray, $devicerecord, $report_id = null)
    {
        $this->type = $type;
        $this->commandName = $commandName;
        $this->configsArray = $configsArray;
        $this->devicerecord = $devicerecord;
        $this->report_id = $report_id;
        $this->model = new Config;
        $this->command = new Command;
        $this->latest_version = new Config;
    }

    public function saveConfigs()
    {
        $savedFileInfo = null;
        $device_category = Category::find($this->devicerecord['device_category_id'])->categoryName;
        $duration = (int) $this->devicerecord['start_time']->diffInSeconds($this->devicerecord['end_time']);

        // rConfig "Keep Unchanged Config": se o conteudo (apos exclusoes) for igual
        // ao ultimo config, nao cria arquivo nem registro.
        if ($this->keepUnchangedEnabled() && $this->newConfigMatchesLatest()) {
            activityLogIt(
                __CLASS__,
                __FUNCTION__,
                'info',
                'Config unchanged - skipped saving (Keep Unchanged Config) for ' . $this->devicerecord['device_name'],
                'connection',
                $this->devicerecord['device_name'],
                $this->devicerecord['id'],
                'device'
            );

            return ['success' => true, 'commandName' => $this->commandName, 'skipped' => true];
        }

        if ($this->configsArray != 0 || $this->configsArray != null) {
            $fileops = new FileOperations(
                $this->commandName,
                $device_category,
                $this->devicerecord['device_name'],
                $this->devicerecord['id'],
                config_data_path(),
                $this->type
            );
            $savedFileInfo = $fileops->saveFile($this->configsArray);
        }

        Config::where('device_id', $this->devicerecord['id'])
            ->where('command', $this->commandName)
            ->update(['latest_version' => 0]);

        $this->model->device_id = $this->devicerecord['id'];
        $this->model->device_name = $this->devicerecord['device_name'];
        $this->model->device_category = $device_category;
        $this->model->command = $this->commandName;
        $this->model->type = $this->type;

        if ($this->configsArray === 0 || $this->configsArray === null) {
            $this->model->download_status = 0;
        } else {
            $this->model->config_location = $savedFileInfo['filepath'];
            $this->model->config_filename = $savedFileInfo['filename'];
            $this->model->config_filesize = $savedFileInfo['filesize'];
            $this->model->download_status = $savedFileInfo['download_status'];
        }

        $this->model->report_id = $this->report_id;
        $this->model->start_time = $this->devicerecord['start_time']->toDateTimeString();
        $this->model->end_time = $this->devicerecord['end_time']->toDateTimeString();
        $this->model->duration = $duration;
        $this->model->latest_version = 1;

        $saved = $this->model->save();

        if ($saved && ! empty($savedFileInfo)) {
            $this->runVersionCompare();

            return ['success' => true, 'commandName' => $this->commandName];
        }

        return ['success' => false, 'commandName' => $this->commandName];
    }

    /**
     * Whether the "Keep Unchanged Config" behaviour is enabled.
     * Read via getenv() because config:cache means env() is empty at runtime.
     */
    private function keepUnchangedEnabled(): bool
    {
        $value = getenv('RCONFIG_KEEP_UNCHANGED');

        if ($value === false || $value === '') {
            return true; // default: enabled
        }

        return filter_var($value, FILTER_VALIDATE_BOOLEAN);
    }

    /**
     * True when the freshly downloaded content is identical (after diff
     * exclusions and whitespace normalisation) to the latest stored config for
     * this device + command. Never throws: on any error returns false so the
     * config is saved normally.
     */
    private function newConfigMatchesLatest(): bool
    {
        if ($this->configsArray === 0 || $this->configsArray === null || $this->configsArray === []) {
            return false;
        }

        $latest = Config::query()
            ->where('device_id', $this->devicerecord['id'])
            ->where('command', $this->commandName)
            ->where('download_status', 1)
            ->orderByDesc('id')
            ->first();

        if (! $latest || empty($latest->config_location) || ! file_exists($latest->config_location)) {
            return false;
        }

        $raw = is_array($this->configsArray) ? implode(PHP_EOL, $this->configsArray) : (string) $this->configsArray;
        if (trim($raw) === '') {
            return false;
        }

        $tmp = tmp_dir() . 'keepunchanged_' . uniqid() . '.txt';
        File::put($tmp, $raw);
        @chmod($tmp, (int) config('rConfig.config_file_mode'));

        try {
            $cleanedNew = (new ConfigCompareExclusionCleaner($tmp, $this->commandName))->excludeLines();
            $newHash = sha1_file($cleanedNew);

            $oldHash = $latest->config_hash;
            if (empty($oldHash)) {
                $cleanedOld = (new ConfigCompareExclusionCleaner($latest->config_location, $this->commandName))->excludeLines();
                $oldHash = sha1_file($cleanedOld);
            }

            if ($newHash === false || $oldHash === false) {
                return false;
            }

            return $newHash === $oldHash;
        } catch (\Throwable $e) {
            Log::error('Keep Unchanged Config: comparison failed for device ' . $this->devicerecord['device_name'] . ': ' . $e->getMessage());

            return false;
        } finally {
            // Remove os temporarios de comparacao (inclui o nosso raw file).
            (new ConfigCompareExclusionCleaner($latest->config_location, $this->commandName))->cleanTempFiles();
        }
    }

    /**
     * Run version + diff detection for a freshly saved config. A failure here
     * must never fail the download, so everything is wrapped and logged.
     */
    private function runVersionCompare(): void
    {
        try {
            (new ConfigHistoryManager)->handleNewDownloadedConfig($this->model, $this->commandName);

            if (! empty($this->model->config_location)) {
                (new ConfigCompareExclusionCleaner($this->model->config_location, $this->commandName))->cleanTempFiles();
            }
        } catch (\Throwable $e) {
            Log::error('Config version compare failed for device ' . $this->model->device_name . ': ' . $e->getMessage());
        }
    }

    public function saveFailedConfigs()
    {
        $this->model->device_id = $this->devicerecord['id'];
        $this->model->device_name = $this->devicerecord['device_name'];
        $this->model->device_category = Category::find($this->devicerecord['device_category_id'])->categoryName;
        $this->model->command = $this->commandName;
        $this->model->type = $this->type;
        $this->model->download_status = 0;
        $this->model->report_id = $this->report_id;
        $this->model->start_time = $this->devicerecord['start_time']->toDateTimeString();
        $this->model->end_time = $this->devicerecord['end_time']->toDateTimeString();
        $this->model->duration = (int) $this->devicerecord['start_time']->diffInSeconds($this->devicerecord['end_time']);
        $this->model->latest_version = 1;
        $this->model->save();

        return ['success' => true, 'commandName' => $this->commandName];
    }
}

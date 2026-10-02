<?php
// Registra (idempotente) os templates custom SSU na tabela `templates` do rConfig.
// Roda dentro do container app:  php /tmp/seed-templates.php
require '/var/www/html/rconfig/vendor/autoload.php';
$app = require '/var/www/html/rconfig/bootstrap/app.php';
$app->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();

use App\Models\Template;

$templates = [
    ['Aruba AOS-S - SSH - No Enable', 'Aruba_AOS_S_SSH_No_Enable.yml'],
    ['HP Comware A5120 - SSH - No Enable - No System View', 'HP_Comware_A5120_SSH_No_Enable_No_System_View.yml'],
    ['HP Comware - SSH - No Enable', 'HP_Comware_SSH_No_Enable.yml'],
    ['Dell Networking - SSH - No Enable', 'Dell_Networking_SSH_No_Enable.yml'],
    ['Aruba AOS-CX - SSH - No Enable', 'Aruba_AOS_CX_SSH_No_Enable.yml'],
    ['Dell N-series (OS6) - SSH - No Enable', 'Dell_OS6_SSH_No_Enable.yml'],
    ['Dell PowerConnect - TELNET - No Enable', 'Dell_PowerConnect_TELNET_No_Enable.yml'],
    ['HP Comware legado - _cmdline (SSH)', 'HP_Comware_Old_Cmdline.yml'],
];

$created = 0;
$updated = 0;
foreach ($templates as [$name, $file]) {
    $fileName = "/app/rconfig/templates/{$file}";
    $t = Template::where('fileName', $fileName)->first();
    if ($t) {
        if ($t->templateName !== $name) {
            $t->templateName = $name;
            $t->save();
            $updated++;
        }
    } else {
        Template::create(['templateName' => $name, 'fileName' => $fileName, 'description' => $name]);
        $created++;
    }
}
echo "templates SSU: {$created} criados, {$updated} atualizados\n";

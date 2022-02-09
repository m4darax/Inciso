#ACA VALIDAMOS LICENCIA
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $login = (Invoke-RestMethod -uri https://"URL"/hour/"EMPRESA_API".json).access
    if ($login -eq "access") {
        $null
    }
    else {
        Write-Host "SISTEMA DESACTUALIZADO"
        Start-Sleep -s 20
        Exit(1)
    }
}
catch {
    Write-Host "ERROR INICIO"
    Start-Sleep -s 5
    exit(1)
}


#ACA OBTENEMOS LA IP DEL VPN
$ip_vpn = (Get-NetIPAddress -InterfaceAlias "Ethernet 4" -AddressFamily "IPv4").IPAddress 2>$null
if ($ip_vpn.length -eq "0") {
    Write-Warning "VPN APAGADO REVISAR"
    Start-Sleep -s 20
    Exit(1)
}else {
    $null
}
#
#Function Test-ADAuthentication { 
#    param($username,$password)
#    #$password = $password.Password
#    $password = [System.Net.NetworkCredential]::new("", $password).Password
#    #LA SIGUIENTE LINEA VALIDARA SI EL USUARIO Y CONTRASEÑA EXISTE
#    $code = (new-object directoryservices.directoryentry "",$username,$password).psbase.name -ne $null
#    if ($code -eq "True") {
#        Write-Host "USUARIO CORRECTO"
#        Clear-Host
#    }
#    else {
#        Write-Host "USUARIO INCORRECTO"
#        Write-Warning "REINICIAR APLICATIVO, VOLVER A INTENTAR"
#        Start-Sleep -s 20
#        Exit(1)
#    }
#}

#FUNCION PARA VALIDAR INICIO DE SESION
Function Test-ADAuthentication { 
    param($username,$password)
    #$password = $password.Password
    $password = [System.Net.NetworkCredential]::new("", $password).Password
    Add-Type -AssemblyName System.DirectoryServices.AccountManagement
    $account = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([DirectoryServices.AccountManagement.ContextType]::Domain, $env:domain)
    $code = $account.ValidateCredentials($username, $password)
    if ($code -eq "True") {
        Write-Host "USUARIO CORRECTO"
        Clear-Host
    }
    else {
        Write-Host "USUARIO INCORRECTO"
        Write-Warning "REINICIAR APLICATIVO, VOLVER A INTENTAR"
        Start-Sleep -s 20
        Exit(1)
    }
}

$username = Read-Host "INGRESA TU USUARIO DE RED"
#$password = Get-Credential -Message "INGRESA USUARIO Y CONTRASEÑA DE RED." -User $username
$password = Read-Host -AsSecureString "INGRESA TU CONTRASENIA DE RED"
Test-ADAuthentication $username $password

#ACA OBTENEMOS LA IP PUBLICA
try {
    $ip_public = Invoke-RestMethod -uri https://api.ipify.org/ 2> $null
}
catch {
    $ip_public = "NOT IP PUBLIC"
}

#ACA OBTENEMOS EL HOST Y USUARIO ACTUAL
$host_user = whoami

#OBTENEMOS HOSTNAME
$hostname = hostname

#OBTENER FECHA PARA LOG REPORTES
$date = Get-Date -Format "yyyy/MM/dd"

function flog_user {
    $date = $date
    $hour = Get-Date -Format "HH:mm:ss"
    $ip_vpn = $ip_vpn
    $ip_public = $ip_public
    $host_user = $host_user
    $hostname = $hostname
    $log_user = $date +","+ $hour +","+ $ip_vpn +","+ $ip_public +","+ $host_user +","+ $hostname
    return ,$log_user
}

#OBTENER LA FECHA Y HORA, DATO QUE SE USARA COMO NOMBRE PARA EL ARCHIVO QUE SE GUARDARA LOS REPORTES
$f1 = Get-Date -Format "yyyyMMdd"
$h1 = Get-Date -Format "HHmmss"
[string]$name_report = $f1 + $h1
#IP DEL SERVIDOR DE REPORTE
$script:IP_SERVER_REPORT = Read-Host "INGRESA LA IP DEL SERVIDOR DE ARCHIVOS"

#OBTENIENDO DATOS DE QUIEN USO LOS ARCHIVOS PARA LOS REPORTES PARA INFORMACION DENTRO DE LOS REPORTES
$MESSAGE_ARCHIVECSV = "INGRESE LA RUTA DEL ARCHIVO .CSV, EJEMPLO (C:\DATOS.CSV)"

Function path_report_server {
    Write-Output "**********************************"
    Write-Host "PROCESO TERMINADO"
    $report = (Get-Location).Path
    Write-Host -BackgroundColor Blue "REPORTE ALMACENANDO EN LA RUTA $report\$name_report.csv"
    [String]$folder = Read-Host "LUEGO DE ESCOGER UNA OPCION EL PROGRAMA SE REINICIARA EN 20 SEGUNDOS`nABRIR LA CARPETA DONDE SE ALMACENA LOS ARCHIVOS [SI/NO]"
    while (($folder -ne "SI") -and ($folder -ne "NO")) {
        [String]$folder = Read-Host "LUEGO DE ESCOGER UNA OPCION EL PROGRAMA SE REINICIARA EN 20 SEGUNDOS`nABRIR LA CARPETA DONDE SE ALMACENA LOS ARCHIVOS [SI/NO]"
    }
    if ($folder -eq "SI") {
        Start-Process explorer.exe $report
        Start-Sleep -s 20
        Clear-Host
        panel
    }
    elseif ($folder -eq "NO") {
        Start-Sleep -s 20
        Clear-Host
        panel
    }
    else {
        Write-Host "EL APLICATIVO SE CERRARA EN 10 SEGUNDOS"
        Start-Sleep -s 10
        Exit(1)
    }
}

function loginoffice365 {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    
    if ((Get-ChildItem "C:\Program Files\WindowsPowerShell\Modules\MSOnline").Name 2> $null ){
        Write-Host "INICIAR SESION CON UN USUARIO PRIVILEGIADO PARA REALIZAR ESTA FUNCION"
    }else {
        Write-Host -ForegroundColor Yellow "MODULO MSONLINE NO INSTALDO"
        Write-Host "POR MOTIVOS DE SEGURIDAD ESTA APLICACION NO SE EJECUTA EN MODO ADMINISTRADOR"
        Write-Host "POR FAVOR EJECUTAR EL SIGUIENTE COMANDO DESDE POWERSHELL EJECUTADO COMO ADMINISTRADOR`nPARA INSTALAR EL MODULO NECESARIO"
        Write-Host -BackgroundColor Blue 'Install-Module Msonline -Force'
        Write-Host "EL PROGRAMA SE CERRARA EN 40 SEGUNDOS"
        Start-Process POWERSHELL -Verb RunAs
        Start-Sleep -s 40
        Exit(1)
    }
    Connect-MsolService 2> $null
    $cod_status = Write-Output $?
    if ($cod_status -eq "True") {
        Write-Host "SERVICIO OFFICE365 CONECTADO"
    }else {
        Write-Warning "NO INICIASTE SESION CON UN USUARIO PRIVILEGIADO EN OFFICE365"
        Write-Warning "EL PROGRAMA SE REINICIARA EN 5 SEGUNDOS"
        Start-Sleep -s 5
        Clear-Host
        panel
    }
}

function loginexchange {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    if (Get-ChildItem "C:\Program Files\WindowsPowerShell\Modules\ExchangeOnlineManagement") {
    }else {
        #Install-Module -Name ExchangeOnlineManagement
        #Unistall-Module -Name ExchangeOnlineManagement
        Write-Host "MODULO EXCHANGEONLINE NO INSTALADO"
        Write-Host "ESTE PROGRAMA NO SE EJECUTA CON PRIVILEGIOS DE ADMINISTRADOR POR SEGURIDAD`nPOR FAVOR EJECUTAR EL SIGUIENTE COMANDO
        EN LA CONSOLA POWERSHELL" 
        Start-Process POWERSHELL -Verb RunAs
        Write-Host "EL PROGRAMA SE CERRARA EN 40 SEGUNDOS"
        Start-Process POWERSHELL -Verb RunAs
        Start-Sleep -s 40
        Exit(1)
    }
    try {
        Write-Host "INICIAR SESION CON UN USUARIO PRIVILEGIADO PARA REALIZAR ESTA FUNCION"
        Connect-ExchangeOnline -ShowBanner:$false -ErrorAction SilentlyContinue 2>$null
    }
    catch {
        Write-Warning "NO INICIASTE SESION CON UN USUARIO PRIVILEGIADO EN OFFICE365"
        Write-Warning "EL PROGRAMA SE REINICIARA EN 5 SEGUNDOS"
        Start-Sleep -s 5
        Clear-Host
        panel
    }
}

function loginazuread {
    if (Get-ChildItem 'C:\Program Files\WindowsPowerShell\Modules\AzureAD' 2> $null) {
        $null
    }else {
        Write-Host -ForegroundColor Yellow "MODULO AZUREAD NO INSTALDO"
        Write-Host "POR MOTIVOS DE SEGURIDAD ESTA APLICACION NO SE EJECUTA EN MODO ADMINISTRADOR"
        Write-Host "POR FAVOR EJECUTAR EL SIGUIENTE COMANDO DESDE POWERSHELL EJECUTADO COMO ADMINISTRADOR`nPARA INSTALAR EL MODULO NECESARIO"
        Write-Host -BackgroundColor Blue 'Install-Module -Name AzureAD -Force'
        Write-Host "EL PROGRAMA SE CERRARA EN 40 SEGUNDOS"
        Start-Process POWERSHELL -Verb RunAs
        Start-Sleep -s 40
        Exit(1)
    }
    Try{
        Write-Host "INICIAR SESION CON UN USUARIO PRIVILEGIADO PARA REALIZAR ESTA FUNCION"
        Connect-AzureAD 2>$null -ErrorAction SilentlyContinue
    }catch{
        Write-Warning "NO INICIASTE SESION CON UN USUARIO PRIVILEGIADO EN OFFICE365"
        Write-Warning "EL PROGRAMA SE REINICIARA EN 5 SEGUNDOS"
        Start-Sleep -s 5
        Clear-Host
        panel
    }
}

function panel {
    #ACA ENVIAMOS EL MENSAJE DE INICIO
    $message = (Invoke-RestMethod -uri https://URL_API/hour/correo.json).message
    Write-Host -BackgroundColor Red $message
    Write-Host "
 #####  #       ####### #     # ####### ######  
#     # #       #       #     # #       #     # 
#       #       #       #     # #       #     # 
#       #       #####   #     # #####   ######  
#       #       #        #   #  #       #   #   
#     # #       #         # #   #       #    #  
 #####  ####### #######    #    ####### #     # 
    
    "
    Write-Host -BackgroundColor Blue "By. Clever Rivera."
    Write-Host "Version. 1.0V `n"
    write-host "BIENVENIDO."
    write-host "Escoge uno de las siguientes opciones:.`n"
    
    Write-Host "OPCIONES PARA INCORPORACIONES"
    write-host -BackgroundColor Red -ForegroundColor White "[1]> VALIDAR USUARIO POR CUENTA AD."
    write-host -BackgroundColor Red -ForegroundColor White "[2]> VALIDAR USUARIO POR DNI."
    write-host -BackgroundColor Red -ForegroundColor White "[3]> ASIGNAR LICENCIAS E1 DE FORMA MASIVA."
    write-host -BackgroundColor Red -ForegroundColor White "[4]> ASIGNAR LISTA DE DISTRIBUCION DE FORMA MASIVA.`n"
    Write-Host "OPCIONES PARA REPORTES"
    write-host -BackgroundColor Red -ForegroundColor White "[5]> REPORTE DE USUARIOS DE AD.`n"
    Write-Host "OPCIONES PARA CESE"
    write-host -BackgroundColor Red -ForegroundColor White "[6]> DESACTIVAR USUARIOS DE FORMA MASIVA EN AD."
    write-host -BackgroundColor Red -ForegroundColor White "[7]> RETIRAR LICENCIAS A USUARIOS EN OFFICE365."
    write-host -BackgroundColor Red -ForegroundColor White "[8]> RETIRAR LISTA DE DISTRIBUCION DE FORMA MASIVA."
#VALIDACION DE OPCIONES DE INGRESO
    try {
        [int]$number = Read-Host "INGRESA LA OPCION"
        while ( $number -ge 9){
            [int]$number = Read-Host "INGRESA LA OPCION"
        }
    }
    catch {
        Write-Warning "OPERACION NO PERMITIDA"
        Start-Sleep -s 3
        Clear-Host
        panel
    }

    if ($number -eq 1) {
        #VALIDACIÓN DE USUARIOS MENDIANTE CUENTA DE AD.
        Clear-Host
        Write-Host -ForegroundColor Red "VALIDACION DE CUENTA AD CON CUENTA DE RED."
        Write-Host "LAS COLUMANAS DEL ARCHIVO .CSV DEBEN CONTENER CUENTA Y TEST"
        Write-Host -BackgroundColor White -ForegroundColor Blue "CUENTA,TEST"
        Write-Host "RESPETAR LAS MAYUSCULAS DE LAS COLUMNAS"
        Write-Output "USUARIO,EXISTE" | Out-File .\$name_report.csv -Append
        Write-Output "USUARIO,EXISTE,FECHA,HORA,IP VPN,IP PUBLICA,USUARIO USADO,HOSTNAME" | Out-File \\$IP_SERVER_REPORT\opcion1\$name_report.csv -Append
        try {
            [String]$ruta = Read-Host $message_archivecsv
            $listado = Import-Csv $ruta
        }
        catch {
            Write-Host "ERROR EN ARCHIVO .CSV"
            Start-Sleep -s 2
            Clear-Host
            panel
        }
        foreach ($usuario in $listado) {
            Start-Sleep -s 1
            $CUENTA1 = $usuario.CUENTA
            $CUENTA = $CUENTA1.Trim()
            if (Get-ADUser -Filter {SamAccountName -eq $CUENTA}){
                Write-Host "$CUENTA"':'"SI EXISTE EN AD"
                $exists = "SI"
                $log_user = flog_user
                $out_report = $CUENTA +","+ $exists +","+ $log_user
                $out_reportuser = $CUENTA +","+ $exists
                Write-Output $out_reportuser | Out-File .\$name_report.csv -Append
                Write-Output $out_report | Out-File  \\$IP_SERVER_REPORT\opcion1\$name_report.csv -Append
            }
            else {
                Write-Host -BackgroundColor Red -ForegroundColor White "$CUENTA"':'"NO EXISTE EN AD"
                $exists = "NO"
                $log_user = flog_user
                $out_report = $CUENTA +","+ $exists +","+ $log_user
                $out_reportuser = $CUENTA +","+ $exists
                Write-Output $out_reportuser | Out-File .\$name_report.csv -Append
                Write-Output $out_report | Out-File \\$IP_SERVER_REPORT\opcion1\$name_report.csv -Append
            }
        }
        path_report_server
    }elseif ($number -eq 2) {
        Clear-Host
        Write-Host -ForegroundColor Red "VALIDACION DE CUENTA AD CON DNI."
        Write-Host "LAS COLUMANAS DEL ARCHIVO .CSV DEBEN CONTENER DNI Y TEST"
        Write-Host -BackgroundColor White -ForegroundColor Blue "DNI,TEST"
        Write-Host "RESPETAR LAS MAYUSCULAS DE LAS COLUMNAS"
        Write-Output "DNI,EXISTE" | Out-File .\$name_report.csv
        Write-Output "DNI,EXISTE,FECHA,HORA,IP VPN,IP PUBLICA,USUARIO USADO,HOSTNAME" | Out-File \\$IP_SERVER_REPORT\opcion2\$name_report.csv
        [string]$path = Read-Host $MESSAGE_ARCHIVECSV
        Import-Csv -Path $path | ForEach-Object {
            $dni1 = $_.DNI
            $dni = $dni1.Trim()
            if (Get-ADUser -Filter {postalCode -like $dni}){
                Write-Host "DNI $dni, SI EXISTE"
                $exists = "SI"
                $out_report = $dni +","+ $exists +","+ $log_user
                $out_reportuser = $dni +","+ $exists
                Write-Output $out_report | Out-File \\$IP_SERVER_REPORT\opcion2\$name_report.csv -Append 
                Write-Output $out_reportuser | Out-File .\$name_report.csv -Append
                
            }else {
                Write-Host -BackgroundColor Red "DNI $dni, NO EXISTE AD"
                $exists = "NO"
                $out_report = $dni +","+ $exists +","+ $log_user
                $out_reportuser = $dni +","+ $exists
                Write-Output $out_report | Out-File \\$IP_SERVER_REPORT\opcion2\$name_report.csv -Append
                Write-Output $out_reportuser | Out-File .\$name_report.csv -Append
            }
        }
        path_report_server
    }elseif ($number -eq 5) {
        Clear-Host
        Write-Host -ForegroundColor Red "ESTA OPCION OBTENDRA UN REPORTE .CSV ."
        Write-Host "ESTA OPCION OBTIENE UN REPORTE .CSV DEL AD.`nEL DATO NECESARIO ES EL DNI DEL USUARIO. COLUMNAS NECESARIAS SON LAS SIGUIENTES."
        Write-Host -BackgroundColor White -ForegroundColor Blue "DNI,TEST"
        Write-Host "RESPETAR LAS MAYUSCULAS DE LAS COLUMNAS"
        try {
            [String]$ruta = Read-Host $message_archivecsv
            $list = Import-Csv $ruta
        }
        catch {
            Write-Host "ERROR EN ARCHIVO .CSV"
            Start-Sleep -s 2
            Clear-Host
            panel
        }
        Write-Output "DNI, ESTADO, NOMBRE COMPLETO, USUARIO, CORREO,FECHA,HORA,IP VPN,IP PUBLICA,USUARIO USADO,HOSTNAME" | Out-File \\$IP_SERVER_REPORT\opcion5\$name_report.csv -Append
        Write-Output "DNI, ESTADO, NOMBRE COMPLETO, USUARIO, CORREO" | Out-File .\$name_report.csv -Append
        foreach ($i in $list) {
            $DNI = $i.DNI
            $code = (Get-ADUser -Filter {postalcode -eq $DNI}).samAccountName
            Write-Output "**********************************"
            if (Get-ADUser -Filter 'postalCode -like $DNI'){
                $value = $code.GetType().name
                if (($code.length -ge "2") -and ($value -notlike "String")){
                    Write-Host "DNI $DNI, DUPLICADO"
                    $out_report = $DNI +","+ ("USUARIO DUPLICADO,"*4) + $log_user
                    $out_reportuser = $DNI +","+ ("USUARIO DUPLICADO,"*4)
                    Write-Output $out_report | Out-File \\$IP_SERVER_REPORT\opcion5\$name_report.csv -Append
                    Write-Output $out_reportuser | Out-File .\$name_report.csv -Append
                }else{
                    Write-Host "DATOS DE DNI $DNI, OBTENIDO Y GUARDADO EN REPORTE"
                    [string]$user = (Get-ADUser -Filter 'postalCode -like $DNI').SamAccountName
                    [string]$display = (Get-ADUser $user -Properties *).DisplayName
                    [string]$status = (Get-ADUser $user -Properties *).Enabled
                    [string]$mail = (Get-ADUser $user -Properties *).UserPrincipalName

                    $out_report = $DNI +","+ $status +","+ $display +","+ $user +","+ $mail +","+ $log_user
                    $out_reportuser = $DNI +","+ $status +","+ $display +","+ $user +","+ $mail
                    Write-Output $out_report | Out-File \\$IP_SERVER_REPORT\opcion5\$name_report.csv -Append
                    Write-Output $out_reportuser | Out-File .\$name_report.csv -Append
                }
            }
            else{
                Write-Host "DNI $DNI, NO EXISTE"
                $out_report = $DNI +","+ ("USUARIO NO EXISTE,"*4) + $log_user
                $out_reportuser = $DNI +","+ ("USUARIO NO EXISTE,"*4)
                Write-Output $out_report | Out-File \\$IP_SERVER_REPORT\opcion5\$name_report.csv -Append
                Write-Output $out_reportuser | Out-File .\$name_report.csv -Append
            }
        }
        path_report_server
    }elseif ($number -eq 6) {
        Clear-Host
        Write-Host -ForegroundColor Red 'ESTA OPCION DESACTIVARA DE FORMA MASIVA CUENTAS AD.'
        Write-Host 'EL DATO NECESARIO PARA DESACTIVAR ES EL DNI Y LAS COLUMAS DEL ARCHIVO .CSV DNI Y TEST'
        Write-Host -BackgroundColor White -ForegroundColor Blue "DNI,TEST"
        Write-Host "RESPETAR LA MAYUSCULA DE LAS COLUMNAS"
        Write-Output "DNI,VPN,OFFICE365,USUARIO,CORREO,FECHA,HORA,IP VPN,IP PUBLICA,USUARIO USADO,HOSTNAME" | Out-File \\$IP_SERVER_REPORT\opcion6\$name_report.csv -Append
        Write-Output "DNI,VPN,OFFICE365,USUARIO,CORREO" | Out-File .\$name_report.csv -Append
        try {
            [String]$ruta = Read-Host $message_archivecsv
            $list = Import-Csv $ruta
        }
        catch {
            Write-Host "ERROR EN ARCHIVO .CSV"
            Start-Sleep -s 2
            Clear-Host
            panel
        }
        foreach ($usuario in $list){
        $DNI = $usuario.DNI 
        Start-Sleep -s 1
        Write-Output "*****************************************"
        if (Get-ADUser -Filter 'PostalCode -like $DNI'){
            $ad = (Get-ADUser -Filter 'PostalCode -Like $DNI').SamAccountName
            try{
                $value = $ad.GetType().name
                if (($ad.length -ge "2") -and ($value -notlike "String")){
                    Write-Output "DNI $DNI, DUPLICADO EN AD"
                    $out_report = $DNI +","+ ("USUARIO DUPLICADO,"*4) + $log_user 
                    $out_reportuser = $DNI +","+ ("USUARIO DUPLICADO,"*4)
                    Write-Output $out_report | Out-File \\$IP_SERVER_REPORT\opcion6\$name_report.csv -Append
                    Write-Output $out_reportuser | Out-File .\$name_report.csv -Append
                }
                else
                { 
                    Disable-ADAccount -Identity $ad
                    Write-Output  "DNI $DNI, DESACTIVADO"
                    $mail = (Get-ADUser -Filter 'PostalCode -Like $DNI').UserPrincipalName
                    $user = (Get-ADUser -Filter 'PostalCode -Like $DNI').SamAccountName
                    $lgroup =(Get-ADPrincipalGroupMembership $user).SamAccountName
                    $365_group = "."
                    $vpn_group = "."
                    foreach ($i in $lgroup){

                        if (($i -eq "Domain Users") -or ($i -eq "Usuarios del dominio")){
                            #Write-Output $mail | Out-File .\mail.txt -Append
                            #Write-Output $user | Out-File .\user.txt -Append
                        }
                        elseif ($i -eq "lic0365-E1-A") {
                            Write-Output "USUARIO TIENE LICENCIA OFFICE365"
                            Remove-ADGroupMember -Identity $i -Members $user -Confirm:$false
                            $365_group = "X"
                        }
                        elseif ($i -eq "VPN_Usuarios") {
                            
                            Write-Output "Se retira acceso a VPN"
                            Remove-ADGroupMember -Identity $i -Members $user -Confirm:$false
                            $vpn_group = "X"
                        }
                        else
                        {
                            Remove-ADGroupMember -Identity $i -Members $user -Confirm:$false
                        }
                    }
                $out_report = $DNI +","+ $vpn_group +","+ $365_group +","+ $user +","+ $mail +","+ $log_user
                $out_reportuser = $DNI +","+ $vpn_group +","+ $365_group +","+ $user +","+ $mail
                Write-Output $out_report | Out-File \\$IP_SERVER_REPORT\opcion6\$name_report.csv -Append
                Write-Output $out_reportuser | Out-File .\$name_report.csv -Append
                Write-Output "GRUPOS RETIRADOS"
                }
            }
            catch
            {
                Write-Output "$DNI NO DESACTIVADO, REVISAR"
                $out_report = $DNI +","+ ("NO DESACTIVADO,"*4) + $log_user
                $out_reportuser = $DNI +","+ ("NO DESACTIVADO,"*4)
                Write-Output $out_report | Out-File \\$IP_SERVER_REPORT\opcion6\$name_report.csv -Append
                Write-Output $out_reportuser | Out-File .\$name_report.csv -Append
            }
        }
        else
        {
            Write-Output "DNI $DNI, NO EXISTE"
            $out_report = $DNI +","+ ("NO EXISTE,"*4) + $log_user
            $out_reportuser = $DNI +","+ ("NO EXISTE,"*4)
            Write-Output $out_report | Out-File \\$IP_SERVER_REPORT\opcion6\$name_report.csv -Append
            Write-Output $out_reportuser | Out-File .\$name_report.csv -Append
        }
            Write-Output "*****************************************"
        }
        path_report_server
    }elseif ($number -eq 7) {
        Clear-Host
        loginoffice365
        Write-Host -ForegroundColor Red 'ESTA OPCION RETIRA LAS LICENAS E1 CESADOS DIRECTAMENTE EN LA CONSOLA365.'
        Write-Host 'EL DATO QUE NECESITA EL ARCHIVO .CSV EN LAS COLUMNAS, SON LOS SIGUIENTES.'
        Write-Host -BackgroundColor Red -ForegroundColor White "CORREO,TEST"
        Write-Host 'RESPETAR LA MAYUSCULA DE LAS COLUMNAS'
        Write-Output "CORREO,LICENCIA,FECHA,HORA,IP VPN,IP PUBLICA,USUARIO USADO,HOSTNAME" | Out-File \\$IP_SERVER_REPORT\opcion7\$name_report.csv -Append
        Write-Output "CORREO,LICENCIA" | Out-File .\$name_report.csv -Append
        try {
            [String]$ruta = Read-Host $message_archivecsv
            $list = Import-Csv $ruta
        }
        catch {
            Write-Host "ERROR EN ARCHIVO .CSV"
            Start-Sleep -s 2
            Clear-Host
            panel
        }
        Write-Host "**********************************"
        foreach ($e in $list){
            $mail1 = $e.CORREO
            $mail =  $mail1.Trim()
            $collection = ((Get-MsolUser -UserPrincipalName $mail | Select-Object *).licenses).AccountSkuId            
            $license = '"'
            if ($mail -like "*@correo.pe") {
                foreach ($i in $collection) {
                    #((Get-MsolUser -UserPrincipalName correo@correo.com | Select-Objetc *).licenses | Select-Object AccountSkuId).AccountSkuId
                    #EN LA SIGUIENTE LINEA DE CODIGO RETIRAMOS LA LICENCIA
                    try {
                        Set-MsolUserLicense -UserPrincipalName $mail -RemoveLicenses $i -ErrorAction Stop
                        Write-Host "LICENCIA RETIRADO, $mail"':'"$i"
                        $license = $license + $i +","
                    }
                    catch {
                        Write-Host -BackgroundColor Red "LICENCIA NO RETIRADO, $mail"':'"$i"
                        $i = $i+"(LICENCIA NO RETIRADO)"
                        $license = $license + $i +","
                    }
                    $out_report = $mail +","+ $license +'"'+","+ $log_user
                    $out_reportuser = $mail +","+ $license +'"'
                    Write-Output $out_report | Out-File \\$path_report_server\opcion7\$name_report.csv -Append
                    Write-Output $out_reportuser | Out-File .\$name_report.csv -Append
            }
            }else {
                Write-Host "$mail, LICENCIA NO RETIRADO, REVISAR"
                $license = $license + "LICENCIA NO RETIRADO"
                $out_report = $mail +","+ $license +'"'+","+ $log_user
                $out_reportuser = $mail +","+ $license +'"'
                Write-Output $out_report | Out-File \\$path_report_server\opcion7\$name_report.csv -Append
                Write-Output $out_reportuser | Out-File .\$name_report.csv -Append

            }
            Write-Host "**********************************"
        }
        path_report_server
    }elseif ($number -eq 3) {
        Clear-Host
        loginoffice365
        Write-Host -ForegroundColor 'EN ESTA OPCION ASIGNARAS LICENCIAS E1 DE FORMA MASIVA DESDE LA CONSOLA365'
        Write-Host "LOS DATOS QUE NECESITA EL ARCHIV .CSV SON LOS SIGUIENTES:"
        Write-Host -BackgroundColor Red -ForegroundColor White "CORREO,TEST"
        Write-Host 'RESPETAR LA MAYUSCULA DE LAS COLUMNAS'
        Write-Output "CORREO,LICENCIA,FECHA,HORA,IP VPN,IP PUBLICA,USUARIO USADO,HOSTNAME" | Out-File \\$IP_SERVER_REPORT\opcion3\$name_report.csv -Append
        Write-Output "CORREO,LICENCIA" | Out-File .\$name_report.csv -Append
        try {
            [String]$ruta = Read-Host $message_archivecsv
            $list = Import-Csv $ruta
        }
        catch {
            Write-Host "ERROR EN ARCHIVO .CSV"
            Start-Sleep -s 2
            Clear-Host
            panel
        }
        foreach ($i in $list) {
            $mail1 = $i.CORREO
            $mail = $mail1.Trim()
            $addlicense = "correo365:STANDARDPACK"
            if ($mail -like "*@correo.pe") {
                try {
                    Set-MsolUserLicense -UserPrincipalName $mail -AddLicenses $addlicense -ErrorAction Stop
                    Write-Host "LICENCIA E1 AGREGADO, $mail"':'"$addlicense"
                    Write-Host -BackgroundColor Blue "LICENCIA NO RETIRADO, $mail"':'"$addlicense"
                    $out_report = $mail +","+ 'LICENCIA NO AGREGADO'
                    $out_report = $mail +","+ 'LICENCIA NO AGREGADO' +","+ $log_user
                    Write-Output $out_report | Out-File \\$path_report_server\opcion3\$name_report.csv -Append
                    Write-Output $out_reportuser | Out-File .\$name_report.csv -Append
                }
                catch {
                    Write-Host -BackgroundColor Blue "LICENCIA NO RETIRADO, $mail"':'"$addlicense"
                    $out_report = $mail +","+ 'LICENCIA NO AGREGADO'
                    $out_report = $mail +","+ 'LICENCIA NO AGREGADO' +","+ $log_user
                    Write-Output $out_report | Out-File \\$path_report_server\opcion3\$name_report.csv -Append
                    Write-Output $out_reportuser | Out-File .\$name_report.csv -Append
                }
            }
            else {
                Write-Host -BackgroundColor Blue "LICENCIA NO RETIRADO, $mail"':'"$addlicense"
                $out_report = $mail +","+ 'LICENCIA NO AGREGADO' +","+ $log_user
                $out_reportuser = $mail +","+ 'LICENCIA NO AGREGADO'
                Write-Output $out_report | Out-File \\$path_report_server\opcion3\$name_report.csv -Append
                Write-Output $out_reportuser | Out-File .\$name_report.csv -Append
            }
        }
        path_report_server
    }elseif ($number -eq 4) {
        Clear-Host
        loginexchange
        Write-Host -ForegroundColor Red 'EN ESTA OPCION AGREGARA CORREOS A LISTA DE DISTRIBUCION DE FORMA MASIVA'
        Write-Host 'LOS DATOS QUE NECESITA EL ARCHIVO .CSV SON LOS SIGUIENTES:'
        Write-Host -BackgroundColor Red -ForegroundColor White "CORREO,SOCIEDAD"
        Write-Host 'RESPETAR LA MAYUSCULA DE LAS COLUMNAS'
        Write-Output "CORREO,SOCIEDAD,AGREGADO,FECHA,HORA,IP VPN,IP PUBLICA,USUARIO USADO,HOSTNAME" | Out-File \\$path_report_server\opcion4\$name_report.csv -Append
        Write-Output "CORREO,SOCIEDAD,AGREGADO" | Out-File .\$name_report.csv -Append
        try {
            [String]$ruta = Read-Host $message_archivecsv
            $list = Import-Csv $ruta
        }
        catch {
            Write-Host "ERROR EN ARCHIVO .CSV"
            Start-Sleep -s 2
            Clear-Host
            panel
        }
        foreach ($i in $list) {
            $society = $i.SOCIEDAD
            $mail = $i.CORREO
            $society = $society.Trim()
            $mail = $mail.Trim()
            function add_list_dist {
                param ($list_dist,$mail,$society,$log_user)
                try {
                    Add-DistributionGroupMember -Identity $list_dist -Member $mail -BypassSecurityGroupManagerCheck -ErrorAction Stop
                    Write-Host "CORREO AGREGADO A SOCIEDAD, $mail"':'"$society"
                    $out_report = $mail +","+ $society +","+"SI"+","+ $log_user
                    $out_reportuser = $mail +","+ $society +","+"SI"
                    Write-Output $out_report  | Out-File \\$path_report_server\opcion4\$name_report.csv -Append
                    Write-Output $out_reportuser | Out-File .\$name_report.csv -Append
                }
                catch {
                    Write-Host -BackgroundColor Red "CORREO NO AGREGADO, $mail':'$society"
                    #$out_report = $mail +","+ $society +","+"NO"+","+ $log_user
                    $out_reportuser = $mail +","+ $society +","+"NO"
                    Write-Output $out_report  | Out-File \\$path_report_server\opcion4\$name_report.csv -Append
                    Write-Output $out_reportuser | Out-File .\$name_report.csv -Append
                }
            }
            switch ($society) {
                'VARIABLE' { 
                    $list_dist = "AQUI_INGRESAR_CORREO@correo.pe"
                    add_list_dist $list_dist $mail $society $log_user
                }
                'VARIABLE'{
                    $list_dist = "AQUI_INGRESAR_CORREO@correo.pe"
                    add_list_dist $list_dist $mail $society $log_user
                }
                'VARIABLE'{
                    $list_dist = "AQUI_INGRESAR_CORREO@correo.pe"
                    add_list_dist $list_dist $mail $society $log_user
                }
                'VARIABLE'{
                    $list_dist = "AQUI_INGRESAR_CORREO@correo.pe"
                    add_list_dist $list_dist $mail $society $log_user
                }
                'VARIABLE'{
                    $list_dist = "AQUI_INGRESAR_CORREO@correo.pe"
                    add_list_dist $list_dist $mail $society $log_user
                }
                'VARIABLE'{
                    $list_dist = "AQUI_INGRESAR_CORREO@correo.pe"
                    add_list_dist $list_dist $mail $society $log_user
                }
                'VARIABLE'{
                    $list_dist = "AQUI_INGRESAR_CORREO@correo.pe"
                    add_list_dist $list_dist $mail $society $log_user
                }
                'VARIABLE'{
                    $list_dist = "AQUI_INGRESAR_CORREO@correo.pe"
                    add_list_dist $list_dist $mail $society $log_user
                }
                'VARIABLE'{
                    $list_dist = "AQUI_INGRESAR_CORREO@correo.pe"
                    add_list_dist $list_dist $mail $society $log_user
                }
                'VARIABLE'{
                    $list_dist = "AQUI_INGRESAR_CORREO@correo.pe"
                    add_list_dist $list_dist $mail $society $log_user
                }
                'VARIABLE'{
                    $list_dist = "correo@correo.pe"
                    add_list_dist $list_dist $mail $society $log_user
                }
                'VARIABLE'{
                    $list_dist = "AQUI_INGRESAR_CORREO"
                    add_list_dist $list_dist $mail $society $log_user
                }
                'VARIABLE'{
                    $list_dist = "AQUI_INGRESAR_CORREO"
                    add_list_dist $list_dist $mail $society $log_user
                }
                'VARIABLE'{
                    $list_dist = "AQUI_INGRESAR_CORREO"
                    add_list_dist $list_dist $mail $society $log_user
                }
                Default { Write-Host "$society SOCIEDAD NO ENCONTRADO, REVISAR"}
            }
        }
        path_report_server
    }elseif ($number -eq 8) {
        Clear-Host
        loginazuread
        Write-Host 'EN ESTA OPCION RETIRAS GRUPOS DE DISTRIBUCION DE FORMA MASIVA'
        Write-Host 'LAS COLUMNAS REQUERIDAS PARA EL ARCHIVO .CSV SON LAS SIGUIENTES:'
        Write-Host -BackgroundColor Red -ForegroundColor White "CORREO,TEST"
        Write-Host 'RESPETAR LA MAYUSCULA DE LA COLUMNA'
        Write-Output "CORREO,SOCIEDAD,RETIRADO,FECHA,HORA,IP VPN,IP PUBLICA,USUARIO USADO,HOSTNAME" | Out-File \\$path_report_server\opcion8\$name_report.csv -Append
        Write-Output "CORREO,SOCIEDAD,AGREGADO" | Out-File .\$name_report.csv -Append
        try {
            [String]$ruta = Read-Host $message_archivecsv
            $list = Import-Csv $ruta
        }
        catch {
            Write-Host "ERROR EN ARCHIVO .CSV"
            Start-Sleep -s 2
            Clear-Host
            panel
        }
        foreach ($item in $list) {
            $CORREO = $item.CORREO
            $CORREO = $CORREO.Trim()
            #AQUI GUARDAMOS EL OBJECTID
            $ob_user = (Get-AzureADUser -ObjectId $CORREO).ObjectID
            #SIGUIENTE LINEA OBTENEMOS EL OBJECTID DEL GRUPO Y DISPLANYNAME
            $ob_usergroup = Get-AzureADUserMembership -ObjectId $ob_user | Select-Object ObjectID,DisplayName
            foreach ($i in $ob_usergroup) {
                $objet_id = $i.ObjectId
                $dis_playname = $i.DisplayName
                try {
                    #AQUI REMOVEMOS EL OBJECTID DEL GRUPO JUNTO CON EL OBJECT DEL USUARIO
                    Remove-AzureADGroupMember -ObjectId $objet_id -MemberId $ob_user -ErrorAction Stop
                    Write-Host "LISTA DE DISTRIBUCION RETIRADO, $CORREO"':'"$dis_playname" 
                    $out_report = $CORREO +","+ $dis_playname +","+"SI"+","+ $log_user
                    $out_reportuser = $CORREO +","+ $dis_playname +","+"SI"
                    Write-Output $out_report  | Out-File \\$path_report_server\opcion8\$name_report.csv -Append
                    Write-Output $out_reportuser | Out-File .\$name_report.csv -Append
                }
                catch {
                    Write-Host -BackgroundColor Red "LISTA DE DISTRIBUCION NO RETIRADO, $CORREO"':'"$dis_playname"
                    $out_report = $CORREO +","+ $dis_playname +","+"NO"+","+ $log_user
                    $out_reportuser = $CORREO +","+ $dis_playname +","+"NO"
                    Write-Output $out_report  | Out-File \\$path_report_server\opcion8\$name_report.csv -Append
                    Write-Output $out_reportuser | Out-File .\$name_report.csv -Append
                }
            }
            path_report_server
        }
    }else {
        Write-Warning 'ERROR INESPERADO'
        Start-Sleep -s 2
        Clear-Host
        panel
    }
}
panel
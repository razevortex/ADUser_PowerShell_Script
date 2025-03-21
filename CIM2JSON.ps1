$instanceProp = @{
                    Bios = @('Name', 'BIOSVersion', 'PrimaryBIOS', 'ReleaseDate')
                    BaseBoard = @('Name', 'Status', 'Manufacturer', 'Product')
                    Processor = @('Name', 'Status', 'Manufacturer', 'Product', 'ProcessorId', 'SocketDesignation', 'NumberOfCores', 'L2CacheSize', 'L3CacheSize', 'MaxClockSpeed', 'LoadPercentage', 'CurrentClockSpeed')
                    VideoController = @('Name', 'Status', 'VideoProcessor', 'AdapterRAM')
                    SoundController = @('Name', 'Status', 'Manufacturer')
                    ComputerSystem = @('Name', 'Domain', 'DomainRole', 'BootupState')
                    PhysicalMemory = @('Manufacturer', 'FormFactor', 'PartNumber', 'BankLabel', 'Capacity', 'Speed')
                    NetworkAdapter = @('Name', 'MACAddress', 'Manufacturer', 'NetConnectionID', 'PhysicalAdapter')
                    DiskDrive = @('DeviceID', 'MediaType', 'BusType', 'Size', 'FriendlyName', 'SerialNumber')
                    Process = @('ProcessId', 'ProcessName', 'Handles', 'KernelModeTime', 'Priority', 'CreationDate', 'UserModeTime', 'ThreadCount')
                    Service = @('Name', 'DisplayName', 'State', 'StartMode', 'Started', 'ProcessId')
                    OperatingSystem = @('Name', 'LastBootUpTime', 'SerialNumber', 'OSArchitexture', 'CSName')
                 }

# Define class/namespace mappings for your simplified names
$classMappings = @{
    Bios             = @{ ClassName = 'Win32_BIOS'; Namespace = 'Root/CIMv2' }
    BaseBoard        = @{ ClassName = 'Win32_BaseBoard'; Namespace = 'Root/CIMv2' }
    Processor        = @{ ClassName = 'Win32_Processor'; Namespace = 'Root/CIMv2' }
    VideoController  = @{ ClassName = 'Win32_VideoController'; Namespace = 'Root/CIMv2' }
    SoundController  = @{ ClassName = 'Win32_SoundDevice'; Namespace = 'Root/CIMv2' }
    ComputerSystem   = @{ ClassName = 'Win32_ComputerSystem'; Namespace = 'Root/CIMv2' }
    PhysicalMemory   = @{ ClassName = 'Win32_PhysicalMemory'; Namespace = 'Root/CIMv2' }
    NetworkAdapter   = @{ ClassName = 'Win32_NetworkAdapter'; Namespace = 'Root/CIMv2' }
    DiskDrive        = @{ ClassName = 'MSFT_PhysicalDisk'; Namespace = 'Root/Microsoft/Windows/Storage' }
    Process          = @{ ClassName = 'Win32_Process'; Namespace = 'Root/CIMv2' }
    Service          = @{ ClassName = 'Win32_Service'; Namespace = 'Root/CIMv2' }
    OperatingSystem  = @{ ClassName = 'Win32_OperatingSystem'; Namespace = 'Root/CIMv2' }
}

# Initialize result object
$output = @{}

foreach ($key in $instanceProp.Keys) {
    $mapping = $classMappings[$key]
    $instances = @()
    
    # Get CIM instances with error handling
    try {
        $cimInstances = Get-CimInstance -ClassName $mapping.ClassName -Namespace $mapping.Namespace -ErrorAction Stop
        
        foreach ($instance in $cimInstances) {
            $props = @{}
            
            # Filter and collect requested properties
            foreach ($propName in $instanceProp[$key]) {
                if ($null -ne $instance.$propName) {
                    # Convert byte arrays to base64 strings if needed (e.g., ProcessorId)
                    if ($instance.$propName -is [byte[]]) {
                        $props[$propName] = [Convert]::ToBase64String($instance.$propName)
                    }
                    else {
                        $props[$propName] = $instance.$propName
                    }
                }
            }
            
            $instances += [PSCustomObject]$props
        }
    }
    catch {
        Write-Warning "Failed to retrieve $($mapping.ClassName): $_"
    }
    
    # Add to output using actual class name as key
    $output[$mapping.ClassName] = $instances
}

# Convert to JSON and save
$output | ConvertTo-Json -Depth 10 | Out-File "sysi_test.json"

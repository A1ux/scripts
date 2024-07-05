# Esxi

## Duplicar una vm

```bash
cd /vmfs/volumes/datastore_name/source_vm_directory
mkdir /vmfs/volumes/datastore_name/destination_vm_directory
cp *.vmdk /vmfs/volumes/datastore_name/destination_vm_directory
cp *.vmx /vmfs/volumes/datastore_name/destination_vm_directory
# Storage > Register a VM > Select .vmx file
# Rename VM
# Start
```
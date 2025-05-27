// Compute resources module
// ...compute-related resources will be moved here from main.bicep...

param sshPublicKeys_genai_jumpbox_vm_01_key_name string = 'genai-jumpbox-vm-01_key'

resource sshPublicKeys_genai_jumpbox_vm_01_key_name_resource 'Microsoft.Compute/sshPublicKeys@2024-11-01' = {
  name: sshPublicKeys_genai_jumpbox_vm_01_key_name
  location: 'canadacentral'
  properties: {
    publicKey: 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCwz5hv9qmSbwcA7ghs8gUbUMA+bofaldsljAOYku8IEzwe/G2srXAmsEf2jIzmG3FH3xioh+ExVYKFs4CmH4OpD/y5gDPMy3Pyh8BEnoQ2M0IWLrlC8Q4vjgW+Vm/g57/ElSWzLJHPIs9bUM8ywGktX9WlOqDlwcLdHpBgHHBsZFPGGX9m/hKtTGFxDq7w+Pa/2kCEgqvssEbIXinJYFZ2V1FUrwfrLQU3FWmKARYjqnFfSUzmkYhcXzrjxs2NOoY46U8bBt+OUHQRm3MfJ8935ZYSwXHckAPdU2UpmlEZ6vp74MBLbL1Q7qlRhVRaFmKj3k00cAWF11mRrOcaK8Vgr+Tw7B0xBkWqNK1cPJd7TO3Sk9j5vMV+XoQ4hKgEGeHpuglxsKS/1sSlhbbvUkIL/ZDVd43wouXJ9t8VOyM2sRxDaPmRsaIn8FxxpISmdRiK8mGia+U2AsOlluMsaPxH+wMh60V4CubF9D/a+E2NWYkOzMNQhZM2xW7Rb1mt0O0= generated-by-azure'
  }
}

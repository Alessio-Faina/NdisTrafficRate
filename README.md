# NdisTrafficRate
Test for connection to NDIS NICs and retrieve traffic informations

Searches for interfaces in the Windows registry

Select the interface you wanna inspect

Every second an output is given with the current Tx/Rx bytes transferred

Works by consulting the NDIS interface via direct IOCTLs, needs Administrative rights to work

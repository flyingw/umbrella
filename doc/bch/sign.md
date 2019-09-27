
# sig brakedown 

>> asn.1 der 
304502210092f3ebac70efdbecf79a5fb1f7cc4ec039b7d41335472fe2292930504c8ce25e02207b4b77906683800f659cb4819a621d58b1c43a35e67fd5659d97ec4cee14790641

30 >> der
    45 - seq lenght 0x45 (69 bytes)
        02 - int element
            21 - element lenght 0x21 (33 bytes)
                0092f3ebac70efdbecf79a5fb1f7cc4ec039b7d41335472fe2292930504c8ce25e ECDSA r value
        02 - integer element
            20 - element lenght 0x20 (32 bytes)
                7b4b77906683800f659cb4819a621d58b1c43a35e67fd5659d97ec4cee147906 ECDSA s value
>> der complete
41 - sighash type | sighash_all | fork_id

package com.opencbs.core.security;

import io.jsonwebtoken.io.Decoders;
import org.springframework.stereotype.Component;

/**
 * Created by Pavel Bastov on 07/01/2017.
 */
@Component
public class SecretKeyProvider {

    private static final String SECRET = "a07364d2b2a68a8620b061f427a2d5f6917c45fb7c2deff2f716cdf54340c71f03226ccaaf68b6368178702a76dec5ba985680d12a35e2ae37f73fe9aae8653ec66afb295f89684f6b82f24bbcb7fc50e9d5f83d5c40e26f6d05e269691b74a2dbe2d7d5a1c2e89727a118491ce5d9d1cd930effa94717c858a20b342e943edcf35a6cc6f852d9679994e0968b6c623c1a6b404bdf26b91ae35e7860f9e2186641b7d5bdc0796a8f1af91e462c26df461ae084b3d4d40850b9ede8d09a5c999193161d4e4d286582e840ace3691a8d1b53d9d713c6cb9740d0b80e5a7fed892c849a9b9ca3a2a5dd06ec52776a0b34ba4e6ee5556985bcf28f56845284260e2453b09a6787d5baaeed505ff8726a9c4f2c80817ba62ee01e0fe74318bbc597589f4f839d2a986f244eba329de36166af7034d04742172d176f74f583280dfcab06473b11bfe09184459ef9833a33400caedc560ad790a090c2040b9a05f3e0ca87483b148a3d23fd4ca196a4747da3bfd28961939eac65651eac0dd43d7e8961bd2108b2331512a22169a423d912e00d4a46b9348865de2d16693c3f1b1c3cf77f4d229256b8aba13e7252ec4b533e22500c2f973d00ce8fa7f342593cf337d8a85bdb12bb78e4151a5380793878806dc03eda68cb5a71eee7d849c3924c022b2a36ea1f59e03b2a39fa7f43fa3693f071b7f444a951512cba211a5a7ed48e63";

    public byte[] getKey() {
        return Decoders.BASE64.decode(SECRET);
    }
}

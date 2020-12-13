/*
 * Copyright 2020 Matt Sicker
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package dev.o1c.test;

import dev.o1c.util.ByteOps;
import dev.o1c.spi.Signature;
import dev.o1c.spi.SignatureFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledIf;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

abstract class SignatureTest {

    abstract SignatureFactory getEd25519();

    abstract SignatureFactory getEd448();

    boolean isEd448Disabled() {
        // some EdDSA providers only support Ed25519
        return false;
    }

    // https://tools.ietf.org/html/rfc8032#section-7.1

    @Test
    void ed25519_emptyMessage() {
        byte[] privateKey = ByteOps.fromHex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        byte[] publicKey = ByteOps.fromHex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        byte[] expectedSignature = ByteOps.fromHex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" +
                "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");

        Signature signature = getEd25519().create();
        assertArrayEquals(expectedSignature, signature.calculateSignature(privateKey, new byte[0]));
        assertTrue(signature.verifySignature(publicKey, new byte[0], expectedSignature));
    }

    @Test
    void ed25519_oneByteMessage() {
        byte[] privateKey = ByteOps.fromHex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
        byte[] publicKey = ByteOps.fromHex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
        byte[] expectedSignature = ByteOps.fromHex("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da" +
                "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");
        byte message = 0x72;

        Signature signature = getEd25519().create();
        assertArrayEquals(expectedSignature, signature.calculateSignature(privateKey, new byte[] { message }));
        assertTrue(signature.verifySignature(publicKey, new byte[] { message }, expectedSignature));
    }

    @Test
    void ed25519_twoByteMessage() {
        byte[] privateKey = ByteOps.fromHex("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7");
        byte[] publicKey = ByteOps.fromHex("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025");
        byte[] expectedSignature = ByteOps.fromHex("6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac" +
                "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a");
        byte[] message = ByteOps.fromHex("af82");

        Signature signature = getEd25519().create();
        assertArrayEquals(expectedSignature, signature.calculateSignature(privateKey, message));
        assertTrue(signature.verifySignature(publicKey, message, expectedSignature));
    }

    @Test
    void ed25519_oneThousandTwentyThreeByteMessage() {
        byte[] privateKey = ByteOps.fromHex("f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5");
        byte[] publicKey = ByteOps.fromHex("278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e");
        byte[] expectedSignature = ByteOps.fromHex("0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350" +
                "aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03");
        byte[] message = ByteOps.fromHex("08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98" +
                "fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d8" +
                "79de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d" +
                "658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc" +
                "1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4fe" +
                "ba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e" +
                "06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbef" +
                "efd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7" +
                "aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed1" +
                "85ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2" +
                "d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24" +
                "554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f270" +
                "88d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc" +
                "2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b07" +
                "07e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128ba" +
                "b27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51a" +
                "ddd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429e" +
                "c96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb7" +
                "51fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c" +
                "42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8" +
                "ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34df" +
                "f7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08" +
                "d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649" +
                "de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e4" +
                "88acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a3" +
                "2ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e" +
                "6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5f" +
                "b93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b5" +
                "0d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1" +
                "369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380d" +
                "b2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c" +
                "0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0");

        Signature signature = getEd25519().create();
        assertArrayEquals(expectedSignature, signature.calculateSignature(privateKey, message));
        assertTrue(signature.verifySignature(publicKey, message, expectedSignature));
    }

    @Test
    void ed25519_shaabc() {
        byte[] privateKey = ByteOps.fromHex("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42");
        byte[] publicKey = ByteOps.fromHex("ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf");
        byte[] expectedSignature = ByteOps.fromHex("dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b589" +
                "09351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704");
        byte[] message = ByteOps.fromHex("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a" +
                "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");

        Signature signature = getEd25519().create();
        assertArrayEquals(expectedSignature, signature.calculateSignature(privateKey, message));
        assertTrue(signature.verifySignature(publicKey, message, expectedSignature));
    }

    // https://tools.ietf.org/html/rfc8032#section-7.4

    @Test
    @DisabledIf("isEd448Disabled")
    void ed448_emptyMessage() {
        byte[] privateKey = ByteOps.fromHex("6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3" +
                "528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b");
        byte[] publicKey = ByteOps.fromHex("5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778" +
                "edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180");
        byte[] expectedSignature = ByteOps.fromHex("533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f" +
                "2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980ff0d2028d4b18a" +
                "9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4db" +
                "b61149f05a7363268c71d95808ff2e652600");

        Signature signature = getEd448().create();
        assertArrayEquals(expectedSignature, signature.calculateSignature(privateKey, new byte[0]));
        assertTrue(signature.verifySignature(publicKey, new byte[0], expectedSignature));
    }

    @Test
    @DisabledIf("isEd448Disabled")
    void ed448_oneByteMessage() {
        byte[] privateKey = ByteOps.fromHex("c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463a" +
                "fbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e");
        byte[] publicKey = ByteOps.fromHex("43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c086" +
                "6aea01eb00742802b8438ea4cb82169c235160627b4c3a9480");
        byte[] expectedSignature = ByteOps.fromHex("26b8f91727bd62897af15e41eb43c377efb9c610d48f2335cb0bd0087810f435" +
                "2541b143c4b981b7e18f62de8ccdf633fc1bf037ab7cd779805e0dbcc0aae1cb" +
                "cee1afb2e027df36bc04dcecbf154336c19f0af7e0a6472905e799f1953d2a0f" +
                "f3348ab21aa4adafd1d234441cf807c03a00");
        byte message = 0x03;

        Signature signature = getEd448().create();
        assertArrayEquals(expectedSignature, signature.calculateSignature(privateKey, new byte[] { message }));
        assertTrue(signature.verifySignature(publicKey, new byte[] { message }, expectedSignature));
    }

    @Test
    @DisabledIf("isEd448Disabled")
    void ed448_oneThousandTwentyThreeByteMessage() {
        var privateKey = ByteOps.fromHex("""
                872d093780f5d3730df7c212664b37b8
                a0f24f56810daa8382cd4fa3f77634ec
                44dc54f1c2ed9bea86fafb7632d8be19
                9ea165f5ad55dd9ce8""");
        var publicKey = ByteOps.fromHex("""
                a81b2e8a70a5ac94ffdbcc9badfc3feb
                0801f258578bb114ad44ece1ec0e799d
                a08effb81c5d685c0c56f64eecaef8cd
                f11cc38737838cf400""");
        var expectedSignature = ByteOps.fromHex("""
                e301345a41a39a4d72fff8df69c98075
                a0cc082b802fc9b2b6bc503f926b65bd
                df7f4c8f1cb49f6396afc8a70abe6d8a
                ef0db478d4c6b2970076c6a0484fe76d
                76b3a97625d79f1ce240e7c576750d29
                5528286f719b413de9ada3e8eb78ed57
                3603ce30d8bb761785dc30dbc320869e
                1a00""");
        var message = ByteOps.fromHex("""
                6ddf802e1aae4986935f7f981ba3f035
                1d6273c0a0c22c9c0e8339168e675412
                a3debfaf435ed651558007db4384b650
                fcc07e3b586a27a4f7a00ac8a6fec2cd
                86ae4bf1570c41e6a40c931db27b2faa
                15a8cedd52cff7362c4e6e23daec0fbc
                3a79b6806e316efcc7b68119bf46bc76
                a26067a53f296dafdbdc11c77f7777e9
                72660cf4b6a9b369a6665f02e0cc9b6e
                dfad136b4fabe723d2813db3136cfde9
                b6d044322fee2947952e031b73ab5c60
                3349b307bdc27bc6cb8b8bbd7bd32321
                9b8033a581b59eadebb09b3c4f3d2277
                d4f0343624acc817804728b25ab79717
                2b4c5c21a22f9c7839d64300232eb66e
                53f31c723fa37fe387c7d3e50bdf9813
                a30e5bb12cf4cd930c40cfb4e1fc6225
                92a49588794494d56d24ea4b40c89fc0
                596cc9ebb961c8cb10adde976a5d602b
                1c3f85b9b9a001ed3c6a4d3b1437f520
                96cd1956d042a597d561a596ecd3d173
                5a8d570ea0ec27225a2c4aaff26306d1
                526c1af3ca6d9cf5a2c98f47e1c46db9
                a33234cfd4d81f2c98538a09ebe76998
                d0d8fd25997c7d255c6d66ece6fa56f1
                1144950f027795e653008f4bd7ca2dee
                85d8e90f3dc315130ce2a00375a318c7
                c3d97be2c8ce5b6db41a6254ff264fa6
                155baee3b0773c0f497c573f19bb4f42
                40281f0b1f4f7be857a4e59d416c06b4
                c50fa09e1810ddc6b1467baeac5a3668
                d11b6ecaa901440016f389f80acc4db9
                77025e7f5924388c7e340a732e554440
                e76570f8dd71b7d640b3450d1fd5f041
                0a18f9a3494f707c717b79b4bf75c984
                00b096b21653b5d217cf3565c9597456
                f70703497a078763829bc01bb1cbc8fa
                04eadc9a6e3f6699587a9e75c94e5bab
                0036e0b2e711392cff0047d0d6b05bd2
                a588bc109718954259f1d86678a579a3
                120f19cfb2963f177aeb70f2d4844826
                262e51b80271272068ef5b3856fa8535
                aa2a88b2d41f2a0e2fda7624c2850272
                ac4a2f561f8f2f7a318bfd5caf969614
                9e4ac824ad3460538fdc25421beec2cc
                6818162d06bbed0c40a387192349db67
                a118bada6cd5ab0140ee273204f628aa
                d1c135f770279a651e24d8c14d75a605
                9d76b96a6fd857def5e0b354b27ab937
                a5815d16b5fae407ff18222c6d1ed263
                be68c95f32d908bd895cd76207ae7264
                87567f9a67dad79abec316f683b17f2d
                02bf07e0ac8b5bc6162cf94697b3c27c
                d1fea49b27f23ba2901871962506520c
                392da8b6ad0d99f7013fbc06c2c17a56
                9500c8a7696481c1cd33e9b14e40b82e
                79a5f5db82571ba97bae3ad3e0479515
                bb0e2b0f3bfcd1fd33034efc6245eddd
                7ee2086ddae2600d8ca73e214e8c2b0b
                db2b047c6a464a562ed77b73d2d841c4
                b34973551257713b753632efba348169
                abc90a68f42611a40126d7cb21b58695
                568186f7e569d2ff0f9e745d0487dd2e
                b997cafc5abf9dd102e62ff66cba87""");

        Signature signature = getEd448().create();
        assertArrayEquals(expectedSignature, signature.calculateSignature(privateKey, message));
        assertTrue(signature.verifySignature(publicKey, message, expectedSignature));
    }
}


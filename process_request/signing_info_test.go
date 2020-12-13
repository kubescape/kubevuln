package process_request

import "testing"

const testSigingProfile1 = `{
    "name": "signing-profile-2-nginx-ingress",
    "guid": "ea9066b5-3b74-4b90-bb77-8553720542cd",
    "platform": 10,
    "architecture": 2,
    "creation_time": "2020-12-09T18:28:51.281111",
    "last_edit_time": "2020-12-09T18:28:51.281120",
    "attributes": {
        "containerName": "nginx-ingress",
        "dockerImageTag": "nginx:1.18.0",
        "dockerImageSHA256": "nginx@sha256:2104430ec73de095df553d0c7c2593813e01716a48d66f85a3dc439e050919b3",
        "generatedFor": "container: nginx-ingress, image: nginx:1.18.0",
        "generatedFrom": "cyberArmor auto generator"
    },
    "executablesList": [
        {
            "mainProcess": "nginx",
            "modulesInfo": [
                {
                    "fullPath": "/usr/sbin/nginx",
                    "name": "nginx",
                    "mandatory": 1,
                    "signatureMismatchAction": 1,
                    "type": 1
                },
                {
                    "fullPath": "/lib/x86_64-linux-gnu/libresolv-2.28.so",
                    "name": "libresolv-2.28.so",
                    "mandatory": 2,
                    "signatureMismatchAction": 1,
                    "type": 1
                },
                {
                    "fullPath": "/lib/x86_64-linux-gnu/libnss_dns-2.28.so",
                    "name": "libnss_dns-2.28.so",
                    "mandatory": 2,
                    "signatureMismatchAction": 1,
                    "type": 1
                },
                {
                    "fullPath": "/lib/x86_64-linux-gnu/libnss_files-2.28.so",
                    "name": "libnss_files-2.28.so",
                    "mandatory": 2,
                    "signatureMismatchAction": 1,
                    "type": 1
                },
                {
                    "fullPath": "/lib/x86_64-linux-gnu/librt-2.28.so",
                    "name": "librt-2.28.so",
                    "mandatory": 2,
                    "signatureMismatchAction": 1,
                    "type": 1
                },
                {
                    "fullPath": "/lib/x86_64-linux-gnu/libc-2.28.so",
                    "name": "libc-2.28.so",
                    "mandatory": 2,
                    "signatureMismatchAction": 1,
                    "type": 1
                },
                {
                    "fullPath": "/lib/x86_64-linux-gnu/libz.so.1.2.11",
                    "name": "libz.so.1.2.11",
                    "mandatory": 2,
                    "signatureMismatchAction": 1,
                    "type": 1
                },
                {
                    "fullPath": "/usr/lib/x86_64-linux-gnu/libcrypto.so.1.1",
                    "name": "libcrypto.so.1.1",
                    "mandatory": 2,
                    "signatureMismatchAction": 1,
                    "type": 1
                },
                {
                    "fullPath": "/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
                    "name": "libssl.so.1.1",
                    "mandatory": 2,
                    "signatureMismatchAction": 1,
                    "type": 1
                },
                {
                    "fullPath": "/lib/x86_64-linux-gnu/libpcre.so.3.13.3",
                    "name": "libpcre.so.3.13.3",
                    "mandatory": 2,
                    "signatureMismatchAction": 1,
                    "type": 1
                },
                {
                    "fullPath": "/lib/x86_64-linux-gnu/libcrypt-2.28.so",
                    "name": "libcrypt-2.28.so",
                    "mandatory": 2,
                    "signatureMismatchAction": 1,
                    "type": 1
                },
                {
                    "fullPath": "/lib/x86_64-linux-gnu/libpthread-2.28.so",
                    "name": "libpthread-2.28.so",
                    "mandatory": 2,
                    "signatureMismatchAction": 1,
                    "type": 1
                },
                {
                    "fullPath": "/lib/x86_64-linux-gnu/libdl-2.28.so",
                    "name": "libdl-2.28.so",
                    "mandatory": 2,
                    "signatureMismatchAction": 1,
                    "type": 1
                },
                {
                    "fullPath": "/lib/x86_64-linux-gnu/ld-2.28.so",
                    "name": "ld-2.28.so",
                    "mandatory": 2,
                    "signatureMismatchAction": 1,
                    "type": 1
                }
            ],
            "filter": {
                "includePaths": [
                    "/usr/sbin/",
                    "/lib/x86_64-linux-gnu/",
                    "/usr/lib/x86_64-linux-gnu/"
                ]
            }
        },
        {
            "mainProcess": "sort",
            "modulesInfo": [
                {
                    "fullPath": "/usr/bin/sort",
                    "name": "sort",
                    "mandatory": 1,
                    "signatureMismatchAction": 1,
                    "type": 1
                },
                {
                    "fullPath": "/lib/x86_64-linux-gnu/libresolv-2.28.so",
                    "name": "libresolv-2.28.so",
                    "mandatory": 2,
                    "signatureMismatchAction": 1,
                    "type": 1
                },
                {
                    "fullPath": "/lib/x86_64-linux-gnu/libnss_dns-2.28.so",
                    "name": "libnss_dns-2.28.so",
                    "mandatory": 2,
                    "signatureMismatchAction": 1,
                    "type": 1
                },
                {
                    "fullPath": "/lib/x86_64-linux-gnu/libnss_files-2.28.so",
                    "name": "libnss_files-2.28.so",
                    "mandatory": 2,
                    "signatureMismatchAction": 1,
                    "type": 1
                },
                {
                    "fullPath": "/lib/x86_64-linux-gnu/librt-2.28.so",
                    "name": "librt-2.28.so",
                    "mandatory": 2,
                    "signatureMismatchAction": 1,
                    "type": 1
                },
                {
                    "fullPath": "/lib/x86_64-linux-gnu/libdl-2.28.so",
                    "name": "libdl-2.28.so",
                    "mandatory": 2,
                    "signatureMismatchAction": 1,
                    "type": 1
                },
                {
                    "fullPath": "/lib/x86_64-linux-gnu/libc-2.28.so",
                    "name": "libc-2.28.so",
                    "mandatory": 2,
                    "signatureMismatchAction": 1,
                    "type": 1
                },
                {
                    "fullPath": "/lib/x86_64-linux-gnu/libpthread-2.28.so",
                    "name": "libpthread-2.28.so",
                    "mandatory": 2,
                    "signatureMismatchAction": 1,
                    "type": 1
                },
                {
                    "fullPath": "/lib/x86_64-linux-gnu/ld-2.28.so",
                    "name": "ld-2.28.so",
                    "mandatory": 2,
                    "signatureMismatchAction": 1,
                    "type": 1
                }
            ],
            "filter": {
                "includePaths": [
                    "/usr/bin/",
                    "/lib/x86_64-linux-gnu/"
                ]
            }
        }
    ]
}`

func TestParseJSON(t *testing.T) {
	sp, ferr := ParseSigningProfileFromJSON([]byte(testSigingProfile1))
	if ferr != nil {
		t.Errorf("JSON parser failed: %s", ferr)
	}
	t.Logf("Parsed %s", sp.Name)
}

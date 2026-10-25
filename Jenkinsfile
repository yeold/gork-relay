// gork-relay on Linux, as a packet socket and through libpcap, through
// test/relaytest.py with real TLS; and both Windows .exe, cross-built with
// MinGW-w64 and linked statically, through the same checks under Wine.
// A v* tag also puts the .exe on the Forgejo release (GitHub's release is
// made by GitHub Actions).  Each in a throwaway container via plain
// `docker run`; containers build as root in their own /tmp and only copy
// finished files into out/, chowned back to the Jenkins user.
pipeline {
    agent { label 'docker' }
    options { buildDiscarder(logRotator(numToKeepStr: '20')) }
    stages {
        stage('build') {
            parallel {
                stage('linux') {
                    steps {
                        sh '''
                            docker run --rm -e TAG_NAME -v "$PWD":/src:ro -e RELAYTEST_TLS=1 debian:stable sh -ec '
                                apt-get -qq update
                                DEBIAN_FRONTEND=noninteractive apt-get -qq install -y --no-install-recommends git gcc libc6-dev make libssl-dev libpcap-dev python3 ca-certificates >/dev/null
                                cp -r /src /tmp/r && cd /tmp/r
                                make CFLAGS="-O2 -Wall -W -Werror" && make check
                                make clean && make PCAP=1 CFLAGS="-O2 -Wall -W -Werror" && make check'
                        '''
                    }
                }
                stage('windows') {
                    steps {
                        sh '''
                            mkdir -p out
                            docker run --rm -e TAG_NAME -v "$PWD":/src:ro -v "$PWD/out":/out fedora:latest sh -ec '
                                dnf -q -y install git make mingw32-gcc mingw32-openssl-static mingw32-zlib-static mingw32-pkg-config mingw64-gcc mingw64-openssl-static mingw64-zlib-static mingw64-pkg-config >/dev/null
                                for a in i686 x86_64; do
                                    cp -r /src /tmp/r-$a && cd /tmp/r-$a && make clean >/dev/null
                                    make WIN=1 CC=$a-w64-mingw32-gcc CFLAGS="-O2 -Wall -W -Werror" LDFLAGS="-static -s" \
                                        SSLLIBS="$($a-w64-mingw32-pkg-config --static --libs openssl)"
                                    cp gork-relay.exe /out/gork-relay-$a.exe
                                done
                                chown -R '"$(id -u):$(id -g)"' /out'
                            # and run each under Wine, 64 and 32 bit
                            docker run --rm -v "$PWD":/src:ro -v "$PWD/out":/out:ro -e RELAYTEST_TLS=1 -e WINEDEBUG=-all debian:stable sh -ec '
                                dpkg --add-architecture i386 && apt-get -qq update
                                DEBIAN_FRONTEND=noninteractive apt-get -qq install -y --no-install-recommends wine wine64 wine32:i386 python3 ca-certificates >/dev/null
                                export WINEPREFIX=/tmp/wp && wineboot -i >/dev/null 2>&1 && wineserver -w
                                cd /src
                                python3 test/relaytest.py wine /out/gork-relay-x86_64.exe
                                python3 test/relaytest.py wine /out/gork-relay-i686.exe'
                        '''
                    }
                }
            }
        }
        stage('release') {
            when { tag 'v*' }
            steps {
                withCredentials([string(credentialsId: 'forgejo-release-token', variable: 'FORGEJO_TOKEN')]) {
                    sh '''
                        git tag -l --format="%(contents)" "$TAG_NAME" >notes.md || true
                        docker run --rm -v "$PWD":/w:ro -w /w -e TAG="$TAG_NAME" -e FORGEJO_TOKEN debian:stable sh -ec '
                            apt-get -qq update
                            DEBIAN_FRONTEND=noninteractive apt-get -qq install -y curl jq ca-certificates >/dev/null
                            NOTES=notes.md sh release.sh out/*.exe'
                    '''
                }
            }
        }
    }
    post {
        success { archiveArtifacts artifacts: 'out/*', fingerprint: true }
        cleanup { sh 'docker image prune -f >/dev/null || true' }
    }
}

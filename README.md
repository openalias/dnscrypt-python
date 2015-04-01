# dnscrypt-python

Copyright (c) 2014-2015, The Monero Project

## Development Resources

Web (OpenAlias): [openalias.org](https://openalias.org)  
Web (Monero): [getmonero.org](https://getmonero.org)  
Forum: [forum.getmonero.org](https://forum.getmonero.org)  
Mail: [dev@getmonero.org](mailto:dev@getmonero.org)  
IRC: [#monero-dev on Freenode](irc://chat.freenode.net/#monero-dev)

## Introduction

OpenAlias seeks to provide a way to simplify aliasing amidst a rapidly shifting technology climate. Users are trying to cross the bridge to private and cryptographically secure infrastructure and systems, but many of them have just barely started remembering the email addresses of their friends and family. At its most basic, OpenAlias is a TXT DNS record on a FQDN (fully qualified domain name). By combining this with DNS-related technologies we have created an aliasing standard that is extensible for developers, intuitive and familiar for users, and can interoperate with both centralised and decentralised domain systems. This is a library that is used to facilitate those lookups.

## About this Project

In order to ensure that lookups do not betray the user's privacy it is best to implement DNSCrypt from OpenDNS, and force resolution via a DNSCrypt-compatible resolver.

The time of this project's inception there were no general use DNSCrypt implementations, and the normal recommended implementation was via [dnscrypt-proxy](https://github.com/jedisct1/dnscrypt-proxy). This makes for a poor user experience, from the perspective of OpenAlias, and so we set out to create a 100% Python implementation for our OpenAlias plugin for the [Electrum Bitcoin wallet](https://electrum.org).

Anyone is able to contribute to dnscrypt-python. If you have a fix or code change, feel free to submit is as a pull request directly to the main branch. In cases where the change is relatively small or does not affect other parts of the codebase it may be merged in immediately by any one of the collaborators. On the other hand, if the change is particularly large or complex, it is expected that it will be discussed at length either well in advance of the pull request being submitted, or even directly on the pull request.

## Supporting the Project

OpenAlias and Monero development can be supported directly through donations.

Both Monero and Bitcoin donations can be made to donate.getmonero.org if using a client that supports the [OpenAlias](https://openalias.org) standard

The Monero donation address is: 46BeWrHpwXmHDpDEUmZBWZfoQpdc6HaERCNmx1pEYL2rAcuwufPN9rXHHtyUA4QVy66qeFQkn6sfK8aHYjA3jk3o1Bv16em (viewkey: e422831985c9205238ef84daf6805526c14d96fd7b059fe68c7ab98e495e5703)

The Bitcoin donation address is: 1FhnVJi2V1k4MqXm2nHoEbY5LV7FPai7bb

## License

Copyright (c) 2014-2015, The Monero Project

All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
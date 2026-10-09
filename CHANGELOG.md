# Changelog

## [0.3.0](https://github.com/aris1009/pySigma-backend-victorialogs/compare/v0.2.0...v0.3.0) (2026-10-09)


### Features

* **backend:** multi-rule correlation search ([#49](https://github.com/aris1009/pySigma-backend-victorialogs/issues/49)) ([e6b50c3](https://github.com/aris1009/pySigma-backend-victorialogs/commit/e6b50c31637c9d25e349d0e429d92d24174e8dcb))


### Bug Fixes

* **ci:** grant workflows permission to release-please app token ([#56](https://github.com/aris1009/pySigma-backend-victorialogs/issues/56)) ([e46600d](https://github.com/aris1009/pySigma-backend-victorialogs/commit/e46600d9d92e6e0d322cb066c3c9a44db65dc0d6))

## [0.2.0](https://github.com/aris1009/pySigma-backend-victorialogs/compare/v0.1.1...v0.2.0) (2026-10-08)


### Features

* **backend:** add grafana_alerting provisioning YAML output format ([#22](https://github.com/aris1009/pySigma-backend-victorialogs/issues/22)) ([ac50e7e](https://github.com/aris1009/pySigma-backend-victorialogs/commit/ac50e7e5f23c9ecf7a59f4961005c21cdd04fc03))
* **release:** sigstore-sign artefacts and enable PEP 740 attestations ([#23](https://github.com/aris1009/pySigma-backend-victorialogs/issues/23)) ([ec4db9d](https://github.com/aris1009/pySigma-backend-victorialogs/commit/ec4db9dc3a5f6e1c08fa6464f5737492d7609043))


### Bug Fixes

* **backend:** parenthesize correlation search to keep _time scope ([#50](https://github.com/aris1009/pySigma-backend-victorialogs/issues/50)) ([0cc8faf](https://github.com/aris1009/pySigma-backend-victorialogs/commit/0cc8fafcd332b1d68fb79826ded2d0f8d1d1c3e4))
* **ci:** raise dependabot cooldown to meet zizmor threshold ([#20](https://github.com/aris1009/pySigma-backend-victorialogs/issues/20)) ([e438dc2](https://github.com/aris1009/pySigma-backend-victorialogs/commit/e438dc20868f3884307b60051feac42663b8a7b5))

## [0.1.1](https://github.com/aris1009/pySigma-backend-victorialogs/compare/v0.1.0...v0.1.1) (2026-05-14)


### Bug Fixes

* **ci:** drop unsupported semver-*-days from github-actions cooldown ([#14](https://github.com/aris1009/pySigma-backend-victorialogs/issues/14)) ([bec64d8](https://github.com/aris1009/pySigma-backend-victorialogs/commit/bec64d8ebf569b65467758c66c458c958bdc66d5))

## 0.1.0 (2026-05-13)


### Features

* initial release of pySigma-backend-victorialogs ([7d9372b](https://github.com/aris1009/pySigma-backend-victorialogs/commit/7d9372b9dfd43a2d41aaa395ede4513d3011ef1e))


### Bug Fixes

* **ci:** green up the four failing workflows on main ([d506438](https://github.com/aris1009/pySigma-backend-victorialogs/commit/d506438b55bdc807d6001e1a042e2369650dbca9))
* **ci:** resolve 12 zizmor + 1 CodeQL code scanning alerts ([#13](https://github.com/aris1009/pySigma-backend-victorialogs/issues/13)) ([e86bf15](https://github.com/aris1009/pySigma-backend-victorialogs/commit/e86bf156e512a084f1c0b41a751117eb702b1684))
* **ci:** scope ruff C901 to sigma/ + bump codeql-action SHA ([#9](https://github.com/aris1009/pySigma-backend-victorialogs/issues/9)) ([b894113](https://github.com/aris1009/pySigma-backend-victorialogs/commit/b8941138dce3e6c18a44f922a4d623093246b90f))
* **compat:** replace datetime.UTC with timezone.utc for Python 3.10 ([#11](https://github.com/aris1009/pySigma-backend-victorialogs/issues/11)) ([0861cf2](https://github.com/aris1009/pySigma-backend-victorialogs/commit/0861cf25e5882af2c5b877f86a309b7cd827fa31))
* **e2e:** repair description block indentation in datasets.yml ([#12](https://github.com/aris1009/pySigma-backend-victorialogs/issues/12)) ([b7d5ed2](https://github.com/aris1009/pySigma-backend-victorialogs/commit/b7d5ed2b2b2eed4716439839ed260f82e5f85922))

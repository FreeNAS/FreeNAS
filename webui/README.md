FreeNAS 11 WebUI
================

This is the project for the new angular.io (4.x) WebUI for FreeNAS 11. It is meant to coexist with current FreeNAS 11 Django/Dojo WebUI.

# Development requirements

  - npm 3
  - Node.js >= 5, < 7
  - Running FreeNAS 11 Nightly (Virtual?) Machine


# Getting started

Install the development requirements (FreeBSD):

```sh
# pkg install node6
# pkg install npm3
```

On some Operating Systems it is quickest to install npm > 3 first then install npm:

```sh
# npm install -g npm3
```

Checkout FreeNAS git repository:

```sh
$ git clone https://github.com/freenas/freenas.git
$ cd freenas/webui
```

Install npm packages:

```sh
$ npm install
```

or (if you installed npm3 with npm4 or later)

```sh
$ npm3 install
```

Start development server pointing to your FreeNAS machine (in this example, address is 192.168.0.50):

```sh
$ env REMOTE=192.168.0.50 npm run server:dev
```

or

```sh
$ env REMOTE=192.168.0.50 npm3 run server:dev
```

This should open the browser with the WebUI, by default http://localhost:3000.

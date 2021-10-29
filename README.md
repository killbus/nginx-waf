## Inspired by
 * https://github.com/PeterDaveHello/ipinfo.tw
 * https://github.com/ADD-SP/ngx_waf
 * https://github.com/allangood/nginx-waf

## Build

If you want to build your own image, instead of directly pull the pre-built one, clone this repository, and run docker build command, with build-arg MAXMIND_LICENSE_KEY, you need to provide your own MaxMind license key from https://www.maxmind.com/en/account, it's free.

```bash
git clone --depth 1 https://github.com/killbus/nginx-waf
cd nginx-ipfilter
docker build --build-arg MAXMIND_LICENSE_KEY="$MY_MAXMIND_KEY" -t nginx-waf:custom-build .
```

You may also need a fixed Nginx version instead.

```bash
docker build --build-arg MAXMIND_LICENSE_KEY="$MY_MAXMIND_KEY" --build-arg NGX_VER="1.21.6" -t nginx-waf:custom-build .
```

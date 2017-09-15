# s2i way of packaging customizations

Source-to-image can be used to create Docker image with baked in customizations.

## Build

```sh
s2i build . quay.io/3scale/apicast:master-builder my-image-name --environment-file=.env
```

The build process should print that it is installing `lua-resty-auto-ssl` module.

## Test

```sh
docker run my-image-name
```

And container will start without any error messages.

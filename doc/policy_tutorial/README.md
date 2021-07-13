# APIcast policy development tutorial
This repository contains the code and configuration of a APIcast policy used in the tutorial described in this README.
It's purposes are to provide a first introduction to the world of policy development.

In this tutorial we are going to dive into the development and testing of a custom APIcast policy. In the first part we are going to setup a development environment so we can actually start the development of our policy.

But before we begin, let’s first take a look what a APIcast policy is. We are not going into too much detail here, since this is described [here](../policies.md).

The APIcast gateway is based on [Nginx](https://www.nginx.com/) and more specifically [Openresty](http://openresty.org/en/), which is a distribution of Nginx compiled with various modules, most notable the [lua-nginx-module](https://github.com/openresty/lua-nginx-module).

The lua-nginx-module provides the ability to enhance a Nginx server by executing scripts using the [Lua programming language](https://www.lua.org/). This is done by providing a Lua hook for each of the Nginx phases. Nginx works using an event loop and a state model where every request (as well as the starting of the server and its worker processes) goes through various phases. Each phase can execute a specific Lua function.

An overview of the various phases and corresponding Lua hooks was kindly in the README of the lua-nginx-module: https://github.com/openresty/lua-nginx-module#directives

![Nginx phases](img/nginx-phases.png)

Since the APIcast gateway uses Openresty a way to leverage these Lua hooks in the Nginx server is provided by something called policies. As described in the APIcast README:

**“The behaviour of APIcast is customizable via policies. A policy basically tells APIcast what it should do in each of the nginx phases.”**

The code in this repo follows the APIcast directory structure.
In order to use this code it has to be integrated in the APIcast code.
Therefore the code and configuration in this repository act for reference purposes only.

The tutorial was 4 distinct sections:
1. [setup the development environment](DEV_ENV_SETUP.md)
2. [generate a policy scaffold](POLICY_SCAFFOLD.md)
3. [create and test the policy](POLICY_IMPLEMENTATION.md)
4. [run the policy locally](POLICY_RUN_LOCALLY.md)
This code is modified version of Shamir's algorithm from: https://github.com/hashicorp/vault/tree/master/shamir.

Original code was using GF(2^8) while we are using GF(2^16) to be able to split secret to more than 255 parts.

Furhtermore, parallelization with go routines was added, and a simple code to generate and verify lookup tables for arbitrary polynomial and generator.
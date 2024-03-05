package fot

import kotlin.random.Random

fun randomBit(): Int = Random.nextInt(2)

fun randomBitsString(n: Int) = (0..n).map { randomBit() }.joinToString(",")
package fot

import kotlin.random.Random

fun randomBit(): Int = Random.nextInt(2)

fun randomBitsString(n: Int) = (0..n).map { randomBit() }.joinToString(",")

fun generateChallengeVector(length: Int, improved: Boolean = false): List<Int> {
    var output: List<Int>
    do {
        output = (0 until length).map { randomBit() }
    } while (improved && !output.contains(1))
    return output
}
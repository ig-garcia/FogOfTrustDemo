import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    kotlin("jvm") version "1.8.21"
    kotlin("plugin.serialization") version "1.8.21"
    application
}

group = "org.example"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    implementation(fileTree(mapOf("dir" to "libs", "include" to listOf("*.jar"))))
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.6.0")
    // https://mvnrepository.com/artifact/org.pgpainless/pgpainless-sop
    implementation("org.pgpainless:pgpainless-sop:1.6.6")

    // https://mvnrepository.com/artifact/org.slf4j/slf4j-jdk14
    implementation("org.slf4j:slf4j-jdk14:2.0.12")
    testImplementation(kotlin("test"))
}

tasks.test {
    useJUnitPlatform()
}

tasks.withType<KotlinCompile> {
    kotlinOptions.jvmTarget = "1.8"
}

application {
    mainClass.set("MainKt")
}
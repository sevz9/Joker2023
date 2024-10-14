package me.markoutte.joker.custom_parse

import me.markoutte.joker.helpers.ComputeClassWriter
import org.apache.commons.cli.DefaultParser
import org.apache.commons.cli.Options
import org.objectweb.asm.*
import java.io.File
import java.lang.reflect.InvocationTargetException
import java.lang.reflect.Method
import java.net.URLClassLoader
import java.nio.ByteBuffer
import java.nio.charset.Charset
import java.nio.file.Files
import java.nio.file.Paths
import java.nio.file.StandardOpenOption
import java.util.concurrent.TimeUnit
import kotlin.io.path.writeBytes
import kotlin.random.Random

@ExperimentalStdlibApi
fun main(args: Array<String>) {
    val options = Options().apply {
        addOption("c", "class", true, "Java class fully qualified name")
        addOption("m", "method", true, "Method to be tested")
        addOption("cp", "classpath", true, "Classpath with libraries")
        addOption("t", "timeout", true, "Maximum time for fuzzing in seconds")
        addOption("s", "seed", true, "The source of randomness")
    }
    val parser = DefaultParser().parse(options, args)
    val className = parser.getOptionValue("class")
    val methodName = parser.getOptionValue("method")
    val classPath = parser.getOptionValue("classpath")
    val timeout = parser.getOptionValue("timeout")?.toLong() ?: 10L
    val seed = parser.getOptionValue("seed")?.toInt() ?: Random.nextInt()
    val random = Random(seed)

    println("Running: $className.$methodName) with seed = $seed")
    val errors = mutableSetOf<String>()
    val b = ByteArray(300)
    val start = System.nanoTime()

    val javaMethod = try {
        loadJavaMethod(className, methodName, classPath)
    } catch (t: Throwable) {
        println("Method $className#$methodName is not found")
        return
    }


    val seeds = mutableMapOf(
        -1 to """<h1>Hello</h1><p>Welcome!</p>""".asByteArray(b.size),
        0 to """<form><input type="text"><input type="submit"></form>""".asByteArray(b.size),
        1 to """ <ul><li>Item 1</li><li>Item 2</li></ul>""".asByteArray(b.size)
    )

    while(System.nanoTime() - start < TimeUnit.SECONDS.toNanos(timeout)) {
        val buffer = seeds.values.randomOrNull(random)?.let(Random::mutate)
            ?: b.apply(random::nextBytes)
        val inputValues = generateInputValues(javaMethod, buffer)
        val inputValuesString = "${javaMethod.name}: ${inputValues.contentDeepToString()}"
        try {
            ExecutionPath.id = 0
            javaMethod.invoke(null, *inputValues).apply {
                val seedId = ExecutionPath.id
                if (seeds.putIfAbsent(seedId, buffer) == null) {
                    println("New seed added: ${seedId.toHexString()}")
                }
            }
        } catch (e: InvocationTargetException) {
            if (errors.add(e.targetException::class.qualifiedName!!)) {
                val errorName = e.targetException::class.simpleName
                println("New error found: $errorName")
                val path = Paths.get("report$errorName.txt")
                Files.write(path, listOf(
                    "${e.targetException.stackTraceToString()}\n",
                    "$inputValuesString\n",
                    "${buffer.contentToString()}\n",
                ))
                Files.write(path, buffer, StandardOpenOption.APPEND)
                println("Saved to: ${path.fileName}")
            }
        }
    }

    println("Seeds found: ${seeds.size}")
    println("Errors found: ${errors.size}")
    println("Time elapsed: ${TimeUnit.NANOSECONDS.toMillis(
        System.nanoTime() - start
    )} ms")
}

fun loadJavaMethod(className: String, methodName: String, classPath: String): Method {
    val libraries = classPath
        .split(File.pathSeparatorChar)
        .map { File(it).toURI().toURL() }
        .toTypedArray()
    val classLoader = object : URLClassLoader(libraries) {
        override fun loadClass(name: String, resolve: Boolean): Class<*> {
            return if (name.startsWith(className.substringBeforeLast('.'))) {
                transformAndGetClass(name).apply {
                    if (resolve) resolveClass(this)
                }
            } else {
                super.loadClass(name, resolve)
            }
        }

        fun transformAndGetClass(name: String): Class<*> {
            val owner = name.replace('.', '/')
            var bytes =
                getResourceAsStream("$owner.class")!!.use { it.readBytes() }
            val reader = ClassReader(bytes)
            val cl = this
            val writer = ComputeClassWriter(
                reader, ClassWriter.COMPUTE_MAXS or ClassWriter.COMPUTE_FRAMES, cl
            )
            val transformer = object : ClassVisitor(Opcodes.ASM9, writer) {
                override fun visitMethod(
                    access: Int,
                    name: String?,
                    descriptor: String?,
                    signature: String?,
                    exceptions: Array<out String>?
                ): MethodVisitor {
                    return object : MethodVisitor(
                        Opcodes.ASM9,
                        super.visitMethod(
                            access, name, descriptor, signature, exceptions
                        )
                    ) {
                        val ownerName =
                            ExecutionPath.javaClass.canonicalName.replace('.', '/')
                        val fieldName = "id"

                        override fun visitLineNumber(line: Int, start: Label?) {
                            visitFieldInsn(
                                Opcodes.GETSTATIC, ownerName, fieldName, "I"
                            )
                            visitLdcInsn(line)
                            visitInsn(Opcodes.IADD)
                            visitFieldInsn(
                                Opcodes.PUTSTATIC, ownerName, fieldName, "I"
                            )
                            super.visitLineNumber(line, start)
                        }
                    }
                }
            }
            reader.accept(transformer, ClassReader.SKIP_FRAMES)
            bytes = writer.toByteArray().also {
                if (name == className) {
                    Paths.get("Instrumented.class").writeBytes(it)
                }
            }
            return defineClass(name, bytes, 0, bytes.size)
        }
    }
    val javaClass = classLoader.loadClass(className)
    val javaMethod = javaClass.declaredMethods.first {
        "${it.name}(${it.parameterTypes.joinToString(",") {
                c -> c.typeName
        }})" == methodName
    }
    return javaMethod
}

fun generateInputValues(method: Method, data: ByteArray): Array<Any> {
    val buffer = ByteBuffer.wrap(data)
    val parameterTypes = method.parameterTypes
    return Array(parameterTypes.size) {
        when (parameterTypes[it]) {
            String::class.java -> String(ByteArray(
                buffer.get().toUByte().toInt() + 1
            ) {
                buffer.get()
            }, Charset.forName("koi8"))
            else -> error("Cannot create value of type ${parameterTypes[it]}")
        }
    }
}

object ExecutionPath {
    @JvmField
    var id: Int = 0
}

fun Random.mutate(input: ByteArray): ByteArray {
    val originalHtml = input.toString(Charsets.UTF_8)
    val builder = originalHtml.toMutableList()

    val probabilities = mapOf(
        "insert_tag" to 0.5,
        "delete_tag" to 0.5,
        "add_invalid_char" to 0.5,
    )

    val tagPattern = """<[^>]+>""".toRegex()
    val tags = tagPattern.findAll(originalHtml).map { it.value }.toList()

    fun randomDecision(probability: Double) = Random.nextDouble() < probability

    fun insertAtRandom(tag: String) {
        val insertionPoint = Random.nextInt(builder.size)
        builder.addAll(insertionPoint, tag.toList())
    }

    if (tags.isNotEmpty() && randomDecision(probabilities["insert_tag"]!!)) {
        insertAtRandom(tags.random())
    }

    if (tags.isNotEmpty() && randomDecision(probabilities["delete_tag"]!!)) {
        val randomTag = tags.randomOrNull()
        val tagStart = builder.joinToString("").indexOf(randomTag.orEmpty())
        if (tagStart != -1) {
            builder.subList(tagStart, tagStart + (randomTag?.length ?: 0)).clear()
        }
    }

    if (randomDecision(probabilities["add_invalid_char"]!!)) {
        val invalidChar = Random.nextInt(32, 127).toChar()
        val insertionPoint = Random.nextInt(builder.size)
        builder.add(insertionPoint, invalidChar)
    }

    return builder.joinToString("").toByteArray(Charsets.UTF_8)
}


fun Any.asByteArray(length: Int): ByteArray? = when (this) {
    is String -> {
        val bytes = toByteArray(Charset.forName("koi8"))
        ByteArray(length) {
            if (it == 0) {
                (bytes.size - 1).toUByte().toByte()
            } else if (it - 1 < bytes.size) {
                bytes[it - 1]
            } else {
                0
            }
        }
    }
    else -> null
}

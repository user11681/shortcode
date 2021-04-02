package user11681.shortcode.tree;

import java.io.IOException;
import java.io.InputStream;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.tree.ClassNode;

public class Klass extends ClassNode {
    public Klass read(byte[] bytecode, int parsingOptions) {
        new ClassReader(bytecode).accept(this, parsingOptions);

        return this;
    }

    public Klass read(InputStream inputStream, int parsingOptions) {
        try {
            new ClassReader(inputStream).accept(this, parsingOptions);
        } catch (IOException throwable) {
            throw new RuntimeException(throwable);
        }

        return this;
    }

    public Klass read(String className, int parsingOptions) {
        try {
            new ClassReader(className).accept(this, parsingOptions);
        } catch (IOException throwable) {
            throw new RuntimeException(throwable);
        }

        return this;
    }

    public byte[] bytecode() {
        return this.bytecode(ClassWriter.COMPUTE_FRAMES);
    }

    public byte[] bytecode(int flags) {
        return this.bytecode(new ClassWriter(flags));
    }

    public byte[] bytecode(ClassWriter writer) {
        this.accept(writer);

        return writer.toByteArray();
    }
}

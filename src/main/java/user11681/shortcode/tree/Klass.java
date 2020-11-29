package user11681.shortcode.tree;

import java.io.IOException;
import java.io.InputStream;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.tree.ClassNode;

public class Klass extends ClassNode {
    public ClassReader reader;
    public ClassWriter writer;

    public Klass() {
        super();
    }

    public void read(final byte[] classFile, final int parsingOptions) {
        this.reader = new ClassReader(classFile);
        this.reader.accept(this, parsingOptions);
    }

    public void read(final InputStream inputStream, final int parsingOptions) {
        try {
            this.reader = new ClassReader(inputStream);
            this.reader.accept(this, parsingOptions);
        } catch (final IOException throwable) {
            throw new RuntimeException(throwable);
        }
    }

    public void read(final String className, final int parsingOptions) {
        try {
            this.reader = new ClassReader(className);
            this.reader.accept(this, parsingOptions);
        } catch (final IOException throwable) {
            throw new RuntimeException(throwable);
        }
    }

    public byte[] toByteArray() {
        return this.toByteArray(ClassWriter.COMPUTE_FRAMES);
    }

    public byte[] toByteArray(final int flags) {
        this.writer = new ClassWriter(flags);
        this.accept(this.writer);

        return this.writer.toByteArray();
    }
}

package user11681.shortcode.type;

import org.objectweb.asm.tree.ClassNode;

public interface TypeUtil {
    static String getInternalName(final Class<?> klass) {
        return toInternalName(klass.getName());
    }

    static String toInternalName(final String binaryName) {
        return binaryName.replace('.', '/');
    }

    static String getBinaryName(final ClassNode klass) {
        return toBinaryName(klass.name);
    }

    static String toBinaryName(final String internalName) {
        return internalName.replace('/', '.');
    }

    static String toDescriptor(final String name) {
        return "L" + toInternalName(name) + ";";
    }
}

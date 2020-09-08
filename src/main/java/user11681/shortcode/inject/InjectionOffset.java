package user11681.shortcode.inject;

import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.InsnList;

public abstract class InjectionOffset {
    public static final InjectionOffset BEFORE = new InjectionBefore();
    public static final InjectionOffset AFTER = new InjectionAfter();

    public abstract void inject(final InsnList target, final InsnList injection, final AbstractInsnNode injectionPoint);

    public static InjectionOffset by(final int offset) {
        return offset >= 0 ? new InjectionByPositive(offset) : new InjectionByNegative(offset);
    }
}

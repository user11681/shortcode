package user11681.shortcode.inject;

import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.InsnList;

public abstract class InjectionOffset {
    public static final InjectionOffset BEFORE = new InjectionBefore();
    public static final InjectionOffset AFTER = new InjectionAfter();

    public abstract void inject(InsnList target, InsnList injection, AbstractInsnNode injectionPoint);

    public static InjectionOffset by(int offset) {
        return offset >= 0 ? new InjectionByPositive(offset) : new InjectionByNegative(offset);
    }
}

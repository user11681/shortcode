package user11681.shortcode.inject;

import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.InsnList;

public class InjectionAfter extends InjectionOffset {
    @Override
    public void inject(final InsnList target, final InsnList injection, final AbstractInsnNode injectionPoint) {
        target.insert(injectionPoint, injection);
    }
}

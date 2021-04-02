package user11681.shortcode.inject;

import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.InsnList;

public class InjectionByNegative extends InjectionOffset {
    public final int offset;

    public InjectionByNegative(int offset) {
        this.offset = -offset - 1;
    }

    @Override
    public void inject(InsnList target, InsnList injection, AbstractInsnNode injectionPoint) {
        final int offset = this.offset;

        for (int i = 0; i < offset; i++) {
            injectionPoint = injectionPoint.getPrevious();
        }

        target.insertBefore(injectionPoint, injection);
    }
}

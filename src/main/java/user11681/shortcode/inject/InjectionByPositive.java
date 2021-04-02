package user11681.shortcode.inject;

import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.InsnList;

public class InjectionByPositive extends InjectionOffset {
    public final int offset;

    public InjectionByPositive(int offset) {
        this.offset = offset;
    }

    @Override
    public void inject(InsnList target, InsnList injection, AbstractInsnNode injectionPoint) {
        final int offset = this.offset;

        for (int i = 0; i < offset; i++) {
            injectionPoint = injectionPoint.getNext();
        }

        target.insert(injectionPoint, injection);
    }
}

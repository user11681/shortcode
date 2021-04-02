package user11681.shortcode.inject;

import java.util.List;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.MethodNode;

public interface Injector {
    static void inject(MethodNode target, InsnList injection, InjectionContext context) {
        inject(target.instructions, injection,context);
    }

    static void inject(final InsnList target, final InsnList injection, final InjectionContext context) {
        final List<AbstractInsnNode> matches = context.findMatches(target);

        for (AbstractInsnNode match : matches) {
            context.offset.inject(target, injection, match);
        }
    }
}

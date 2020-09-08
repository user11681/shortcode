package user11681.shortcode.inject;

import it.unimi.dsi.fastutil.objects.ReferenceArrayList;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.MethodNode;

public interface Injector {
    static void inject(final MethodNode target, final InsnList injection, final InjectionContext context) {
        inject(target.instructions, injection,context);
    }

    static void inject(final InsnList target, final InsnList injection, final InjectionContext context) {
        final ReferenceArrayList<AbstractInsnNode> matches = context.findMatches(target);
        final int size = matches.size();

        for (int i = 0; i < size; i++) {
            context.offset.inject(target, injection, matches.get(i));
        }
    }
}

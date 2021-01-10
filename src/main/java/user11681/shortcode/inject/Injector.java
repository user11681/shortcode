package user11681.shortcode.inject;

import it.unimi.dsi.fastutil.objects.ReferenceArrayList;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.MethodNode;

public interface Injector {
    static void inject(MethodNode target, InsnList injection, InjectionContext context) {
        inject(target.instructions, injection,context);
    }

    static void inject(InsnList target, InsnList injection, InjectionContext context) {
        final ReferenceArrayList<AbstractInsnNode> matches = context.findMatches(target);
        final int size = matches.size();

        for (int i = 0; i < size; i++) {
            context.offset.inject(target, injection, matches.get(i));
        }
    }
}

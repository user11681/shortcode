package user11681.shortcode;

import java.io.File;
import java.net.URL;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Debug {
    private static final Logger logger = LogManager.getLogger("GrossFabricHacks/test");

    public static void printFields(Class<?> klass, Object object) {
        Arrays.stream(klass.getDeclaredFields()).forEach(field -> {
            try {
                final Object value = field.get(object);
                final String message = String.format("%s = %s", field, value != null && value.getClass().isArray() ? Arrays.deepToString((Object[]) value) : value);

<<<<<<< HEAD
                for (final String line : message.split("\n")) {
                    logger.info(line);
=======
                for (String line : message.split("\n")) {
                    LOGGER.info(line);
>>>>>>> 194643b10fc2a6877e9582ba2c304beddde121b7
                }
            } catch (IllegalAccessException exception) {
                System.exit(768);
            }
        });
    }

    public static void listR(URL resource) {
        listR(resource.getFile());
    }

    public static void listR(String file) {
        listR(new File(file));
    }

    public static void listR(File file) {
        listR(file, 0);
    }

    public static void listR(File file, int level) {
        final StringBuilder output = new StringBuilder();

        for (int i = 0; i < level; i++) {
            output.append("    ");
        }

        if (file.isFile()) {
            output.append(file);

            logger.error(output);
        } else {
            if (level == 0) {
                output.append(file);
            } else {
                output.append(file.getName().substring(file.getName().lastIndexOf('/') + 1));
            }

            logger.warn(output);

            for (File feil : file.listFiles()) {
                listR(feil, level + 1);
            }
        }
    }
}

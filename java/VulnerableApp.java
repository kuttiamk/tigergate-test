import java.io.IOException;

public class VulnerableApp {
    
    // Vulnerability 1: Hardcoded AWS Keys
    public static final String AWS_SECRET_KEY = "aws_secret_key=AKIAIOSFODNN7EXAMPLE";

    public static void main(String[] args) {
        if (args.length > 0) {
            String command = args[0];
            try {
                // Vulnerability 2: OS Command Injection
                // Flaw: executing arbitrary commands without validation
                Runtime.getRuntime().exec(command);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}

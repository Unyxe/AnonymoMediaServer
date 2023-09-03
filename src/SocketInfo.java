import java.net.Socket;
import java.util.ArrayList;

public class SocketInfo {
    public String socket_id;
    public Socket socket;

    public String auth = "";
    public boolean isAuthorized = false;
    public SocketInfo(String socket_id_, Socket socket_){
        socket_id = socket_id_;
        socket = socket_;
    }
}

import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.net.*;

public class main {
    static Random rn = new Random();

    static int max_messages_per_page = 50;
    public static void main(String[] args) throws IOException {

        String http_resp_headers =
                "HTTP/2 200 OK\n" +
                "Server: Vastly\n" +
                "Content-Type: application/json; charset=UTF-8\n\n";

        ServerSocket serverSocket = new ServerSocket(8085);
        Thread t = new Thread(()->{
            while(true){
                try {
                    //System.out.println("Waiting for connection...");
                    Socket socket = serverSocket.accept();
                    Thread q = new Thread(()->{
                        try {
                            String socket_id = rn.nextInt() + "";
                            SocketInfo socketInfo = new SocketInfo(socket_id, socket);
                            DB.sockets.add(socketInfo);

                            System.out.println("[DEBUG] Socket("+socket_id+") created!");
                            InputStream input = socket.getInputStream();
                            OutputStream output = socket.getOutputStream();

                            boolean is_packet_data = false;
                            int packet_length = 0;
                            ArrayList<Byte> byte_list = new ArrayList<>();

                            try {
                                while (true) {
                                    if (packet_length <= 0) {
                                        is_packet_data = false;
                                        if (byte_list.size() > 0) {
                                            output.write(PacketResponse(ToByteArray(byte_list), socketInfo));
                                        }
                                    }
                                    if (is_packet_data) {
                                        byte_list.add((byte) input.read());
                                        packet_length--;
                                    } else {
                                        is_packet_data = true;
                                        byte_list.clear();
                                        int a = input.read();
                                        packet_length = input.read() + 256 * a;
                                    }
                                }
                            }catch(Exception e){
                                for(int i = 0; i < DB.sockets.size();i++){
                                    if(DB.sockets.get(i).socket_id.equals(socket_id)){
                                        DB.sockets.remove(DB.sockets.get(i));
                                        break;
                                    }
                                }
                                System.out.println("[DEBUG] Socket exception (probably closed by a client)");
                            }
                        } catch (Exception e) {
                            throw new RuntimeException(e);
                        }
                    });
                    q.start();
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        });
        t.start();
    }

    static byte[] ToByteArray(ArrayList<Byte> list){
        byte[] b = new byte[list.size()];
        for(int i = 0; i < b.length;i++){
            b[i] = list.get(i);
        }
        return b;
    }
    static byte[] PacketResponse(byte[] input_packet, SocketInfo socketInfo) {
        String status = "success";
        String packet_str = null;
        try {
            packet_str = new String(input_packet, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }

        String[] packet_spl = packet_str.split(" ");

        String method = packet_spl[0];

        root_switch:
        switch(method){
            case "login":
            {
                if(packet_spl.length == 3){
                    String username = packet_spl[1];
                    String password = packet_spl[2];
                    String auth_token = LogIn(username, password);
                    if(auth_token == "-1"){
                        status = "failed";
                    } else if(auth_token == "-2"){
                        status = "failed";
                    }
                    System.out.println("[DEBUG] LogIn attempt: " + status);
                    if(status == "success"){
                        socketInfo.auth = auth_token;
                        socketInfo.isAuthorized = true;
                        try {
                            socketInfo.socket.getOutputStream().write(StringToPacket("auth " + auth_token));
                        } catch (IOException e) {
                            throw new RuntimeException(e);
                        }
                    }
                }else{
                    status = "failed";
                }
            }
            break;
            case "register":
            {
                if(packet_spl.length == 3){
                    String username = packet_spl[1];
                    String password = packet_spl[2];
                    String st = Register(username, password);
                    if(st == "-1"){
                        status = "failed";
                    } else if(st == "-2"){
                        status = "failed";
                    }
                    System.out.println("[DEBUG] Register attempt: " + status);
                }else{
                    status = "failed";
                }
            }
            break;
            case "logout":
            {
                if(!socketInfo.isAuthorized) {
                    status = "not_authorized";
                    break root_switch;
                }
                if(packet_spl.length == 0){
                    LogOut(socketInfo);
                    System.out.println("[DEBUG] LogOut attempt: " + status);
                }else{
                    status = "failed";
                }
            }
            break;
            case "create_chat":
            {
                if(!socketInfo.isAuthorized) {
                    status = "not_authorized";
                    break root_switch;
                }
                if(packet_spl.length == 2){
                    String auth = socketInfo.auth;
                    String chat_display_name = packet_spl[1];
                    String chat_id = CreateChat(auth, chat_display_name);
                    if(chat_id == "-4041"){
                        status = "failed";
                    }
                    System.out.println("[DEBUG] Chat creation attempt: " + status);
                    if(status == "success"){
                        try {
                            socketInfo.socket.getOutputStream().write(StringToPacket("new_chat " + GetEncodedChat(chat_id)));
                        } catch (IOException e) {
                            throw new RuntimeException(e);
                        }
                    }
                }else{
                    status = "failed";
                }
            }
            break;
            case "delete_chat":
            {
                if(!socketInfo.isAuthorized) {
                    status = "not_authorized";
                    break root_switch;
                }
                if(packet_spl.length == 2){
                    String auth = socketInfo.auth;
                    String chat_id = packet_spl[1];
                    String st = DeleteChat(auth, chat_id);
                    if(st == "-4041"){
                        status = "failed";
                    } else if(st == "-4042"){
                        status = "failed";
                    }
                    System.out.println("[DEBUG] Chat deletion attempt: " + status);
                    if(status == "success"){
                        for(String member_name : DB.chats.get(GetChatById(chat_id)).members){
                            SendToAllSockets(GetAuthByUsername(member_name), "remove_chat " + chat_id);
                        }
                    }
                }else{
                    status = "failed";
                }
            }
            break;
            case "add_member":
            {
                if(!socketInfo.isAuthorized) {
                    status = "not_authorized";
                    break root_switch;
                }
                if(packet_spl.length == 3){
                    String auth = socketInfo.auth;
                    String chat_id = packet_spl[1];
                    String member_name = packet_spl[2];
                    String st = AddMember(auth, chat_id, member_name);
                    if(st == "-4041"){
                        status = "failed";
                    } else if(st == "-4042"){
                        status = "failed";
                    }else if(st == "-4043"){
                        status = "failed";
                    }else if(st == "-4031"){
                        status = "failed";
                    }else if(st == "-4011"){
                        status = "failed";
                    }
                    if(status == "success"){
                        SendToAllSockets(GetAuthByUsername(member_name),"new_chat " + chat_id);
                    }
                    System.out.println("[DEBUG] Add member attempt: " + status);
                }else{
                    status = "failed";
                }
            }
            break;
            case "remove_member":
            {
                if(!socketInfo.isAuthorized) {
                    status = "not_authorized";
                    break root_switch;
                }
                if(packet_spl.length == 3){
                    String auth = socketInfo.auth;
                    String chat_id = packet_spl[1];
                    String member_name = packet_spl[2];
                    String st = RemoveMember(auth, chat_id, member_name);
                    if(st == "-4041"){
                        status = "failed";
                    } else if(st == "-4042"){
                        status = "failed";
                    }else if(st == "-4031"){
                        status = "failed";
                    }else if(st == "-4011"){
                        status = "failed";
                    }
                    if(status == "success"){
                        SendToAllSockets(GetAuthByUsername(member_name),"member_delete " + chat_id);
                    }
                    System.out.println("[DEBUG] Remove member attempt: " + status);
                }else{
                    status = "failed";
                }
            }
            break;
            case "send_message":
            {
                if(!socketInfo.isAuthorized) {
                    status = "not_authorized";
                    break root_switch;
                }
                if(packet_spl.length == 3){
                    String auth = socketInfo.auth;
                    String chat_id = packet_spl[1];
                    String message = packet_spl[2];
                    String st = SendMessage(auth, chat_id, message);
                    if(st == "-4041"){
                        status = "failed";
                    } else if(st == "-4042"){
                        status = "failed";
                    }else if(st == "-4031"){
                        status = "failed";
                    }

                    System.out.println("[DEBUG] Send message attempt: " + status);
                }else{
                    status = "failed";
                }
            }
            break;
            case "get_chats":
            {
                if(!socketInfo.isAuthorized) {
                    status = "not_authorized";
                    break root_switch;
                }
                if(packet_spl.length == 1){
                    String auth = socketInfo.auth;
                    String chats_encoded = GetChatsForMemberEncoded(auth);
                    if(chats_encoded == "-4041"){
                        status = "failed";
                    }
                    if(status == "success"){
                        try {
                            socketInfo.socket.getOutputStream().write(StringToPacket("chats_response " + chats_encoded));
                        } catch (IOException e) {
                            throw new RuntimeException(e);
                        }
                    }
                    System.out.println("[DEBUG] Chats request attempt: " + status);
                }else{
                    status = "failed";
                }
            }
            break;
            case "get_messages":
            {
                if(!socketInfo.isAuthorized) {
                    status = "not_authorized";
                    break root_switch;
                }
                if(packet_spl.length == 3){
                    String auth = socketInfo.auth;
                    String chat_id = packet_spl[1];
                    int page = -1;
                    try {
                        page = Integer.parseInt(packet_spl[2]);
                    }catch(Exception e){
                        status ="failed";
                        break root_switch;
                    }
                    String messages_encoded = GetChatHistoryPageEncoded(auth, chat_id, page);
                    if(messages_encoded == "-4041"){
                        status = "failed";
                    } else if(messages_encoded == "-4042"){
                        status = "failed";
                    }else if(messages_encoded == "-4031"){
                        status = "failed";
                    } else if(messages_encoded == "-5001"){
                        status = "failed";
                    }
                    if(status == "success"){
                        try {
                            socketInfo.socket.getOutputStream().write(StringToPacket("messages_response " + messages_encoded + " " + chat_id));
                        } catch (IOException e) {
                            throw new RuntimeException(e);
                        }
                    }
                    System.out.println("[DEBUG] Message history request attempt: " + status);
                }else{
                    status = "failed";
                }
            }
            break;
            case "get_members":
            {
                if(!socketInfo.isAuthorized) {
                    status = "not_authorized";
                    break root_switch;
                }
                if(packet_spl.length == 2){
                    String auth = socketInfo.auth;
                    String chat_id = packet_spl[1];
                    String members_encoded = GetMembersForChatEncoded(auth, chat_id);
                    if(members_encoded == "-4041"){
                        status = "failed";
                    } else if(members_encoded == "-4042"){
                        status = "failed";
                    }else if(members_encoded == "-4031"){
                        status = "failed";
                    }
                    if(status == "success"){
                        try {
                            socketInfo.socket.getOutputStream().write(StringToPacket("members_response " + members_encoded + " " + chat_id));
                        } catch (IOException e) {
                            throw new RuntimeException(e);
                        }
                    }
                    System.out.println("[DEBUG] Chat's members request attempt: " + status);
                }else{
                    status = "failed";
                }
            }
            break;
            default:
            {
                status = "non_existing_method";
            }
            break;
        }



        return StringToPacket(method+" " + status);
    }



    static String GetChatHistoryPageEncoded(String auth, String chat_id, int page){
        int user_index = GetUserByAuth(auth);
        if(user_index == -1) return "-4041";
        String username = DB.users.get(user_index)[0];
        int chat_index = GetChatById(chat_id);
        if(chat_index == -1) return "-4042";
        Chat chat = DB.chats.get(chat_index);
        if(!chat.members.contains(username)) return "-4031";
        if(page*max_messages_per_page > chat.chat_history.size()-1) return "-5001";
        ArrayList<String[]> messages = new ArrayList<>();
        int m = (page+1)*max_messages_per_page;
        if(m > chat.chat_history.size()){
            m = chat.chat_history.size();
        }

        for(int i = page*max_messages_per_page; i < m;i++){
            messages.add(i, chat.chat_history.get(i));
        }
        return GetEncodedMessages(messages.toArray(new String[messages.size()][]));
    }
    static String GetMembersForChatEncoded(String auth, String chat_id){
        int user_index = GetUserByAuth(auth);
        if(user_index == -1) return "-4041";
        String username = DB.users.get(user_index)[0];
        int chat_index = GetChatById(chat_id);
        if(chat_index == -1) return "-4042";
        Chat chat = DB.chats.get(chat_index);
        if(!chat.members.contains(username)) return "-4031";

        return GetEncodedMembers(chat.members.toArray(new String[chat.members.size()]));
    }
    static String GetChatsForMemberEncoded(String auth){
        ArrayList<String> chat_ids = new ArrayList<>();
        int user_index = GetUserByAuth(auth);
        if(user_index == -1) return "-4041";
        String username = DB.users.get(user_index)[0];
        for(int i = 0 ; i < DB.chats.size();i++){
            Chat c = DB.chats.get(i);
            if(c.members.contains(username)){
                chat_ids.add(c.chat_id);
            }
        }
        return GetEncodedChats(chat_ids.toArray(new String[chat_ids.size()]));
    }
    static String SendMessage(String auth, String chat_id, String message){
        int user_index = GetUserByAuth(auth);
        if(user_index == -1) return "-4041";
        String username = DB.users.get(user_index)[0];
        int chat_index = GetChatById(chat_id);
        if(chat_index == -1) return "-4042";
        if(!DB.chats.get(chat_index).members.contains(username)) return "-4031";
        DB.chats.get(chat_index).chat_history.add(0, new String[]{username, message});
        for(int i = 0; i < DB.chats.get(chat_index).members.size();i++){
            String member_auth = GetAuthByUsername(DB.chats.get(chat_index).members.get(i));
            SendToAllSockets(member_auth, "new_msg " + chat_id + " " + EncodeBase64(message) + " " + username);
        }
        return "0";
    }
    static String AddMember(String auth, String chat_id, String member_username){
        int user_index = GetUserByAuth(auth);
        if(user_index == -1) return "-4041";
        String username = DB.users.get(user_index)[0];
        int chat_index = GetChatById(chat_id);
        if(chat_index == -1) return "-4042";
        String chat_owner_username = DB.chats.get(chat_index).owner_username;
        if(chat_owner_username.equals(username)){
            if(DB.chats.get(chat_index).members.contains(member_username)) return "-4011";
            if(GetAuthByUsername(member_username) == null) return "-4043";
            DB.chats.get(chat_index).members.add(member_username);
        }else{
            return "-4031";
        }
        return "0";
    }
    static String RemoveMember(String auth, String chat_id, String member_username){
        int user_index = GetUserByAuth(auth);
        if(user_index == -1) return "-4041";
        String username = DB.users.get(user_index)[0];
        int chat_index = GetChatById(chat_id);
        if(chat_index == -1) return "-4042";
        String chat_owner_username = DB.chats.get(chat_index).owner_username;
        if(chat_owner_username.equals(username)){
            if(!DB.chats.get(chat_index).members.contains(member_username)) return "-4011";
            DB.chats.get(chat_index).members.remove(member_username);
        }else{
            return "-4031";
        }
        return "0";
    }
    static String CreateChat(String auth, String chat_display_name){
        int user_index = GetUserByAuth(auth);
        if(user_index == -1) return "-4041";
        String username = DB.users.get(user_index)[0];
        String chat_id = Hash(rn.nextInt()+"");
        DB.chats.add(new Chat(username, chat_id, chat_display_name));
        return chat_id;
    }
    static String DeleteChat(String auth, String chat_id){
        int user_index = GetUserByAuth(auth);
        if(user_index == -1) return "-4041";
        String username = DB.users.get(user_index)[0];
        int chat_index = GetChatById(chat_id);
        if(chat_index == -1) return "-4042";
        String chat_owner_username = DB.chats.get(chat_index).owner_username;
        if(chat_owner_username.equals(username)){
            DB.chats.remove(DB.chats.get(chat_index));
        } else{
            return "-4031";
        }
        return "0";
    }
    static String LogOut(SocketInfo socketInfo){
        socketInfo.isAuthorized = false;
        socketInfo.auth = "";
        return "0";
    }
    static String Register(String u, String p){
        for(int i = 0; i < DB.users.size();i++){
            String[] user_info = DB.users.get(i);
            if(u.equals(user_info[0])){
                return "-1";
            }
        }
        DB.users.add(new String[]{u, Hash(p), Hash(u+p+"08052008")});
        return "0";
    }
    static String LogIn(String u, String p){
        for(int i = 0; i < DB.users.size();i++){
            String[] user_info = DB.users.get(i);
            if(Objects.equals(u, user_info[0])){
                if(Objects.equals(Hash(p), user_info[1])){
                    return user_info[2];
                } else{
                    return "-1";
                }
            }
        }
        return "-2";
    }
    static String Hash(String s){
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(s.getBytes());
            byte[] digest = md.digest();
            String hex = "";
            for (byte i : digest) {
                hex += String.format("%02X", i);
            }
            return hex;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
    static void SendToAllSockets(String auth, String message){
        for(int j = 0; j < DB.sockets.size();j++){
            if(DB.sockets.get(j).auth.equals(auth)){
                try {
                    DB.sockets.get(j).socket.getOutputStream().write(StringToPacket(message));
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
        }
    }
    static byte[] StringToPacket(String msg)
    {
        if(msg.length() > 255 * 256 + 255 * 1)
        {
            System.out.println("Message is too big!");
            return null;
        }
        byte[] packet = new byte[msg.length() + 2];
        int a = msg.length() / 255;
        int b = msg.length() % 255;
        packet[0] = (byte)a;
        packet[1] = (byte)b;
        for(int i = 0; i < msg.length(); i++)
        {
            packet[i+2] = msg.getBytes()[i];
        }
        return packet;
    }

    static int GetUserByAuth(String auth){
        for(int i = 0; i < DB.users.size();i++){
            if(DB.users.get(i)[2].equals(auth)){
                return i;
            }
        }
        return -1;
    }

    static String GetAuthByUsername(String username){
        for(int i = 0; i < DB.users.size();i++){
            if(DB.users.get(i)[0].equals(username)){
                return DB.users.get(i)[2];
            }
        }
        return null;
    }
    static int GetChatById(String id){
        for(int i = 0; i < DB.chats.size();i++){
            if(DB.chats.get(i).chat_id.equals(id)){
                return i;
            }
        }
        return -1;
    }

    static String GetEncodedChat(String chat_id){
        String chat_display_name = DB.chats.get(GetChatById(chat_id)).display_name;
        return EncodeBase64(chat_id + " " + chat_display_name);
    }

    static String GetEncodedChats(String[] chat_ids){
        String d = "";
        for(int i = 0; i < chat_ids.length;i++){
            String chat_display_name = DB.chats.get(GetChatById(chat_ids[i])).display_name;
            d += chat_ids[i] + " " + chat_display_name;
            if(i == chat_ids.length-1){
                break;
            }
            d += "\n";
        }
        return EncodeBase64(d);
    }
    static String GetEncodedMembers(String[] member_names){
        String d = "";
        for(int i = 0; i < member_names.length;i++){
            d += member_names[i];
            if(i == member_names.length-1){
                break;
            }
            d += " ";
        }
        return EncodeBase64(d);
    }
    static String GetEncodedMessages(String[][] messages){
        String d = "";
        for(int i = 0; i < messages.length;i++){
            String message_body = messages[i][1];
            String sender = messages[i][0];
            d += sender + " "+EncodeBase64(message_body);
            if(i == messages.length-1){
                break;
            }
            d += "\n";
        }
        return EncodeBase64(d);
    }
    
    static String DecodeBase64(String s){
        return new String(Base64.getDecoder().decode(s));
    }
    static String EncodeBase64(String s){
        return Base64.getEncoder().encodeToString(s.getBytes());
    }
}

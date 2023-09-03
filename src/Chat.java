import java.util.ArrayList;

public class Chat {
    public String chat_id;
    public String display_name;
    public String owner_username;
    public ArrayList<String> members = new ArrayList<>();
    public ArrayList<String[]> chat_history = new ArrayList<>();
    public Chat(String owner_username_, String chat_id_, String display_name_){
        chat_id = chat_id_;
        display_name = display_name_;
        owner_username = owner_username_;
        members.add(owner_username);
    }
}

package com.vulnerax.modules.notification;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import java.util.*;
@Service @RequiredArgsConstructor
public class NotificationService {
    private final NotificationRepository repo;
    public Notification send(Notification n){
        n.setStatus("SENT");
        return repo.save(n);
    }
    public List<Notification> list(UUID projectId){ return projectId!=null? repo.findByProjectId(projectId): repo.findAll(); }
    public Notification get(UUID id){ return repo.findById(id).orElseThrow(); }
}

package models;

import jakarta.persistence.*;

@Entity
@Table(name = "users")
public class UserEntity {

    @Id
    @Column(name = "user_id", nullable = false)
    private Long userId;

    @Column(name = "email")
    protected String email;

    @javax.persistence.Column(name = "created")
    java.time.Instant created;

    @Column(name = "pwd")
    private final String password;

    @Column(name = "status")
    private Integer status = 0;

    @Column(name = "full_name")
    public String getFullName() {
        return email;
    }
}

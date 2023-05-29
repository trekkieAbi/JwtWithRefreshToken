package com.refresh.token.model;

import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;
import java.time.Instant;
@Getter
@Setter
@Entity(name = "refresh_token")
public class RefreshToken {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "refresh_token_id")
    private Integer id;
    @OneToOne
    @JoinColumn(name="user_id_fk",referencedColumnName = "user_id")
    private User user;
    @Column(nullable = false,unique = true,name = "refresh_token")
    private String token;
    @Column(nullable = false,name = "refresh_token_expiry_date")
    private Instant expiryDate;

}

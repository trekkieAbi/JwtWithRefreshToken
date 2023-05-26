package com.refresh.token.model;

import lombok.Getter;
import lombok.Setter;

import java.util.Set;

import javax.persistence.*;
@Getter
@Setter
@Entity
@Table(name = "roles")
public class Role {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "role_id")
    private Integer id;

    @Enumerated(EnumType.STRING)
    @Column(length = 20)
    private ERole name;
    @ManyToMany(cascade = CascadeType.ALL,fetch = FetchType.LAZY,mappedBy = "roles")
    private Set<User> user;

    public Integer getId() {
		return id;
	}

	public void setId(Integer id) {
		this.id = id;
	}

	public ERole getName() {
		return name;
	}

	public void setName(ERole name) {
		this.name = name;
	}

	public Role() {

    }

    public Role(ERole name) {
        this.name = name;
    }

}

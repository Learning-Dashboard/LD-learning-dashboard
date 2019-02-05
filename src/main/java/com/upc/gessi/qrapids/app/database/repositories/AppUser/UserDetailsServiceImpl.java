package com.upc.gessi.qrapids.app.database.repositories.AppUser;

import com.upc.gessi.qrapids.app.domain.models.AppUser;
import com.upc.gessi.qrapids.app.domain.repositories.AppUser.CustomUserRepository;
import com.upc.gessi.qrapids.app.domain.repositories.AppUser.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import static java.util.Collections.emptyList;

@Service
public class UserDetailsServiceImpl implements UserDetailsService, CustomUserRepository {

	@PersistenceContext
	private EntityManager entityManager;

	private UserRepository userRepository;

	public UserDetailsServiceImpl(UserRepository userRepository) {
		this.userRepository = userRepository;
	}

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		AppUser appUser = userRepository.findByUsername(username);
		if (appUser == null) {
			throw new UsernameNotFoundException(username);
		}
		return new org.springframework.security.core.userdetails.User(appUser.getUsername(), appUser.getPassword(), emptyList());
	}

	@Override
	public AppUser findUserByEmail(String email) {
		AppUser result = null;

		result = this.entityManager.createQuery("FROM AppUser AS u WHERE u.email = :email", AppUser.class)
				.setParameter("email", email)
				.getSingleResult();

		return result;
	}
}

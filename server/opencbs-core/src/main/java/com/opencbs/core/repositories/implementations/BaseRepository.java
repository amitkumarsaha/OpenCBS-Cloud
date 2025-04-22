package com.opencbs.core.repositories.implementations;

import com.opencbs.core.domain.BaseEntity;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.persistence.criteria.CriteriaQuery;
import org.apache.poi.ss.formula.functions.T;
import org.hibernate.Criteria;
import org.hibernate.Session;
import org.springframework.beans.factory.annotation.Autowired;

public abstract class BaseRepository<Tentity extends BaseEntity> {

    protected EntityManager entityManager;
    protected Class<Tentity> clazz;

    public BaseRepository(EntityManager entityManager, Class<Tentity> clazz) {
//        this.entityManager = entityManager;
        this.clazz = clazz;
    }

//    protected Criteria createCriteria(String alias) {
//        return getSession().createCriteria(clazz, alias);
//    }

    protected CriteriaQuery<?> createCriteria(String alias) {
        return createCriteria(clazz, alias);
    }

//    protected Criteria createCriteria(Class clazz, String alias) {
//        return getSession().createCriteria(clazz, alias);
//    }

    protected CriteriaQuery<?> createCriteria(Class<?> type, String alias) {
        return getSession().getCriteriaBuilder().createQuery(alias, type);
    }

    protected EntityManager getEntityManager() {
        return this.entityManager;
    }

    private Session getSession() {
        return entityManager.unwrap(Session.class);
    }
}

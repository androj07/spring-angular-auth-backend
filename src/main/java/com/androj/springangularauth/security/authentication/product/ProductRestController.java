package com.androj.springangularauth.security.authentication.product;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.PostConstruct;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/product")
public class ProductRestController {

    private final Map<Long, Product> mockedData = new HashMap<>();

    @PostConstruct
    public void postConstruct() {
        mockedData.put(1L, new Product(1, "Witcher 1"));
        mockedData.put(2L, new Product(2, "Witcher 2"));
        mockedData.put(3L, new Product(3, "Witcher 3"));
        mockedData.put(4L, new Product(4, "Horizon Zero Dawn"));
    }

    @GetMapping
    Collection<Product> getProducts() {
        return mockedData.values();
    }
}

package com.opencbs.core.accounting.dto;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.NotNull;
import java.math.BigDecimal;

@RequiredArgsConstructor
@Getter
public class MultipleTransactionAmountDto {
    @DecimalMin(value = "0.0")
    private final BigDecimal amount;
    @NotNull
    private final Long accountId;
}

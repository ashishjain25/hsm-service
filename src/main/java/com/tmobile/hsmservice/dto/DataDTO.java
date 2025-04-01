package com.tmobile.hsmservice.dto;

import jakarta.validation.constraints.NotNull;

public record DataDTO(@NotNull(message = "Please provide data to be encrypted") String data) {
}

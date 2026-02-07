package compliance

is_prod if { lower(input.context.env) == "prod" }
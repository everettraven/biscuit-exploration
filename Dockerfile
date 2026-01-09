FROM golang:1.25

COPY . .

RUN go build -o k8s-biscuit main.go

ENTRYPOINT [ "./k8s-biscuit", "run" ]


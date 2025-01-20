FROM alpine:3.21.2 AS base

ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Create a non-root user and group
RUN addgroup -S appuser && adduser -S appuser -G appuser

RUN apk add --no-cache python3

FROM base AS build

COPY requirements.txt .

RUN apk add --no-cache \
    py3-pip

USER appuser

RUN pip install --break-system-packages --user --no-cache-dir -r requirements.txt

FROM base AS runner

RUN apk add --no-cache gcc

# Set permissions for the application directory
COPY main.py /app

COPY --chown=appuser:appuser --from=build /home/appuser/.local /home/appuser/.local

# Update PATH for installed Python packages for alpine
ENV PATH=/app/.local/bin:$PATH
RUN echo 'export "PATH=$PATH:/app/.local/bin"' >> /etc/profile

RUN chown -R appuser:appuser /app

USER appuser

LABEL version="0.1.0"

CMD ["python", "main.py"]

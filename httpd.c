// httpd.c
#define _GNU_SOURCE
#include "net.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <errno.h>
#include <inttypes.h>

void sigchld_handler(int s) {
   // Wait for all dead processes.
   while (waitpid(-1, NULL, WNOHANG) > 0);
}

void handle_request(int nfd) {
   FILE *network = fdopen(nfd, "r+");
   char *line = NULL;
   size_t size = 0;
   ssize_t num;

   if (network == NULL) {
      perror("fdopen");
      close(nfd);
      return;
   }

   // Read the request line
   num = getline(&line, &size, network);
   if (num <= 0) {
      free(line);
      fclose(network);
      return;
   }

   // Parse the request line
   char method[5], request_uri[2048], http_version[16];
   if (sscanf(line, "%4s %2047s %15s", method, request_uri, http_version) != 3) {
      // Bad request
      fprintf(network, "HTTP/1.0 400 Bad Request\r\n");
      fprintf(network, "Content-Type: text/html\r\n");
      fprintf(network, "Content-Length: 15\r\n");
      fprintf(network, "\r\n");
      fprintf(network, "400 Bad Request");
      free(line);
      fclose(network);
      return;
   }

   // Ignore the HTTP version
   (void)http_version;

   // Check if method is GET or HEAD
   if (strcmp(method, "GET") != 0 && strcmp(method, "HEAD") != 0) {
      // Not Implemented
      fprintf(network, "HTTP/1.0 501 Not Implemented\r\n");
      fprintf(network, "Content-Type: text/html\r\n");
      fprintf(network, "Content-Length: 19\r\n");
      fprintf(network, "\r\n");
      fprintf(network, "501 Not Implemented");
      free(line);
      fclose(network);
      return;
   }

   // Process the request URI
   char *path = NULL;
   char *query = NULL;

   // Separate path and query string
   char *question_mark = strchr(request_uri, '?');
   if (question_mark != NULL) {
      // There is a query string
      *question_mark = '\0';
      path = request_uri;
      query = question_mark + 1;
   } else {
      // No query string
      path = request_uri;
      query = NULL;
   }

   // Prevent directory traversal
   if (strstr(path, "..") != NULL) {
      // Forbidden
      fprintf(network, "HTTP/1.0 403 Permission Denied\r\n");
      fprintf(network, "Content-Type: text/html\r\n");
      fprintf(network, "Content-Length: 21\r\n");
      fprintf(network, "\r\n");
      fprintf(network, "403 Permission Denied");
      free(line);
      fclose(network);
      return;
   }

   // Check if the request is for a CGI-like program
   if (strncmp(path, "/cgi-like/", 10) == 0 && strlen(path) > 10) {
      // Handle CGI-like execution
      // Extract the program name
      char program_name[1024];
      snprintf(program_name, sizeof(program_name), "%s", path + 10);

      // Build the arguments array
      char *args[256];
      int arg_count = 0;

      args[arg_count++] = program_name; // Program name without leading path

      if (query != NULL) {
         // Split the query string into arguments
         char *arg = strtok(query, "&");
         while (arg != NULL && arg_count < 255) {
            args[arg_count++] = arg;
            arg = strtok(NULL, "&");
         }
      }

      args[arg_count] = NULL; // Null-terminate the argument list

      // Before forking, block SIGCHLD
      sigset_t newmask, oldmask;
      sigemptyset(&newmask);
      sigaddset(&newmask, SIGCHLD);

      if (sigprocmask(SIG_BLOCK, &newmask, &oldmask) == -1) {
         perror("sigprocmask");
         free(line);
         fclose(network);
         return;
      }

      // Fork a child process
      pid_t pid = fork();
      if (pid == -1) {
         // Fork failed
         perror("fork");
         fprintf(network, "HTTP/1.0 500 Internal Error\r\n");
         fprintf(network, "Content-Type: text/html\r\n");
         fprintf(network, "Content-Length: 21\r\n");
         fprintf(network, "\r\n");
         fprintf(network, "500 Internal Error");
         // Unblock SIGCHLD before returning
         sigprocmask(SIG_SETMASK, &oldmask, NULL);
         free(line);
         fclose(network);
         return;
      } else if (pid == 0) {
         // Child process
         // Unblock SIGCHLD in child
         sigprocmask(SIG_SETMASK, &oldmask, NULL);
         // Redirect stdout to a temporary file
         char temp_filename[256];
         snprintf(temp_filename, sizeof(temp_filename), "temp_output_%d.txt", getpid());

         int fd = open(temp_filename, O_WRONLY | O_CREAT | O_TRUNC, 0600);
         if (fd == -1) {
            perror("open");
            exit(1);
         }

         if (dup2(fd, STDOUT_FILENO) == -1) {
            perror("dup2");
            close(fd);
            exit(1);
         }
         close(fd);

         // Change directory to ./cgi-like
         if (chdir("./cgi-like") == -1) {
            perror("chdir");
            exit(1);
         }

         // Execute the program
         execvp(args[0], args);
         // If execvp returns, there was an error
         perror("execvp");
         exit(1);
      } else {
         // Parent process
         // Wait for the child process to finish
         int status;
         if (waitpid(pid, &status, 0) == -1) {
            perror("waitpid");
            fprintf(network, "HTTP/1.0 500 Internal Error\r\n");
            fprintf(network, "Content-Type: text/html\r\n");
            fprintf(network, "Content-Length: 21\r\n");
            fprintf(network, "\r\n");
            fprintf(network, "500 Internal Error");
            // Unblock SIGCHLD before returning
            sigprocmask(SIG_SETMASK, &oldmask, NULL);
            free(line);
            fclose(network);
            return;
         }

         // Unblock SIGCHLD after waitpid
         if (sigprocmask(SIG_SETMASK, &oldmask, NULL) == -1) {
            perror("sigprocmask");
            free(line);
            fclose(network);
            return;
         }

         // Check if child exited successfully
         if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            // Child process failed
            fprintf(network, "HTTP/1.0 500 Internal Error\r\n");
            fprintf(network, "Content-Type: text/html\r\n");
            fprintf(network, "Content-Length: 21\r\n");
            fprintf(network, "\r\n");
            fprintf(network, "500 Internal Error");
            free(line);
            fclose(network);
            return;
         }

         // Read the output file
         char temp_filename[256];
         snprintf(temp_filename, sizeof(temp_filename), "temp_output_%d.txt", pid);

         int output_fd = open(temp_filename, O_RDONLY);
         if (output_fd == -1) {
            perror("open output file");
            fprintf(network, "HTTP/1.0 500 Internal Error\r\n");
            fprintf(network, "Content-Type: text/html\r\n");
            fprintf(network, "Content-Length: 21\r\n");
            fprintf(network, "\r\n");
            fprintf(network, "500 Internal Error");
            free(line);
            fclose(network);
            return;
         }

         // Get file size
         struct stat st;
         if (fstat(output_fd, &st) == -1) {
            perror("fstat");
            close(output_fd);
            fprintf(network, "HTTP/1.0 500 Internal Error\r\n");
            fprintf(network, "Content-Type: text/html\r\n");
            fprintf(network, "Content-Length: 21\r\n");
            fprintf(network, "\r\n");
            fprintf(network, "500 Internal Error");
            free(line);
            fclose(network);
            return;
         }

         // Send response headers
         fprintf(network, "HTTP/1.0 200 OK\r\n");
         fprintf(network, "Content-Type: text/html\r\n");
         fprintf(network, "Content-Length: %" PRId64 "\r\n", (int64_t)st.st_size);
         fprintf(network, "\r\n");
         fflush(network);

         // If method is GET, send the content
         if (strcmp(method, "GET") == 0) {
            char buffer[1024];
            ssize_t bytes_read;
            while ((bytes_read = read(output_fd, buffer, sizeof(buffer))) > 0) {
               fwrite(buffer, 1, bytes_read, network);
            }
            fflush(network);
         }

         close(output_fd);

         // Remove the temporary file
         if (unlink(temp_filename) == -1) {
            perror("unlink");
         }
      }
   } else {
      // Handle as a regular file request
      // Remove leading '/'
      char filepath[1024];
      if (path[0] == '/')
         snprintf(filepath, sizeof(filepath), ".%s", path);
      else
         snprintf(filepath, sizeof(filepath), "%s", path);

      // Open the file
      int fd = open(filepath, O_RDONLY);
      if (fd == -1) {
         // Not Found
         fprintf(network, "HTTP/1.0 404 Not Found\r\n");
         fprintf(network, "Content-Type: text/html\r\n");
         fprintf(network, "Content-Length: 13\r\n");
         fprintf(network, "\r\n");
         fprintf(network, "404 Not Found");
         free(line);
         fclose(network);
         return;
      }

      // Get file size
      struct stat st;
      if (fstat(fd, &st) == -1) {
         // Internal Server Error
         fprintf(network, "HTTP/1.0 500 Internal Error\r\n");
         fprintf(network, "Content-Type: text/html\r\n");
         fprintf(network, "Content-Length: 21\r\n");
         fprintf(network, "\r\n");
         fprintf(network, "500 Internal Error");
         close(fd);
         free(line);
         fclose(network);
         return;
      }

      // Send response headers
      fprintf(network, "HTTP/1.0 200 OK\r\n");
      fprintf(network, "Content-Type: text/html\r\n");
      fprintf(network, "Content-Length: %" PRId64 "\r\n", (int64_t)st.st_size);
      fprintf(network, "\r\n");
      fflush(network);

      // If method is GET, send the file contents
      if (strcmp(method, "GET") == 0) {
         char buffer[1024];
         ssize_t bytes_read;
         while ((bytes_read = read(fd, buffer, sizeof(buffer))) > 0) {
            fwrite(buffer, 1, bytes_read, network);
         }
         fflush(network);
      }

      close(fd);
   }

   // Keep the connection open until client closes it
   // Read and discard any additional data
   while ((num = getline(&line, &size, network)) >= 0) {
      // Do nothing
   }

   free(line);
   fclose(network);
}

void run_service(int fd) {
   // Install signal handler for SIGCHLD
   struct sigaction sa;
   sa.sa_handler = sigchld_handler;
   sigemptyset(&sa.sa_mask);
   sa.sa_flags = SA_RESTART;
   if (sigaction(SIGCHLD, &sa, NULL) == -1) {
      perror("sigaction");
      exit(1);
   }

   while (1) {
      int nfd = accept_connection(fd);
      if (nfd != -1) {
         pid_t pid = fork();
         if (pid == 0) {
            // Child process
            close(fd); // Close listening socket in child
            handle_request(nfd);
            close(nfd);
            exit(0);
         } else if (pid > 0) {
            // Parent process
            close(nfd); // Parent doesn't need this
         } else {
            perror("fork");
            close(nfd);
         }
      }
   }
}

int main(int argc, char *argv[]) {
   if (argc != 2) {
      fprintf(stderr, "Usage: %s <port>\n", argv[0]);
      exit(1);
   }

   int port = atoi(argv[1]);

   int fd = create_service(port);

   if (fd == -1) {
      perror("create_service");
      exit(1);
   }

   printf("Listening on port: %u\n", port);
   run_service(fd);
   close(fd);

   return 0;
}

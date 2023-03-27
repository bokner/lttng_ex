defmodule Lttng do
  @moduledoc """

  Interface to LTTng

  """

  @erlang_dyntrace_domain :org_erlang_dyntrace
  @erlang_otp_domain :org_erlang_otp

  defp default_opts do
    [
      session: "default_session",
      events: [:function_call, :function_return],
      patterns: []
    ]
  end

  def syscalls() do
    System.cmd("lttng", ["list", "--kernel", "--syscall"])
    |> then(fn {out, _} ->
      [_header, _sepline | calls] = String.split(out, "\n")

      Enum.map(calls, fn call ->
        call
        |> String.split("[")
        |> hd
        |> String.trim()
      end)
    end)
  end

  def kernel_events() do
    System.cmd("lttng", ["list", "--kernel"])
    |> then(fn {out, _} ->
      [_header, _sepline | calls] = String.split(out, "\n")

      Enum.map(calls, fn call ->
        call
        |> String.split("(loglevel:")
        |> hd
        |> String.trim()
      end)
    end)
  end

  def userspace_tracepoints() do
    {message, 0} = System.cmd("lttng", ["list", "-u"])

    String.split(message, "\n")
    |> Enum.flat_map(fn str ->
      case String.split(str, " ", trim: true) do
        [] ->
          []

        [first | _rest] ->
          (String.contains?(first, ":") && [first]) || []
      end
    end)
  end

  def erlang_tracepoints() do
    userspace_tracepoints()
    |> Enum.filter(fn tp -> String.starts_with?(tp, "org_erlang") end)
  end

  def start_tracing(opts) do
    opts = Keyword.merge(default_opts(), opts)
    true = Code.ensure_loaded?(:dyntrace)
    :ok = create_lttng_session(opts)
    :ok = enable_events(opts)
    :ok = start_lttng(opts)
    :ok = start_vm_tracing(opts)
  end

  def stop_tracing() do
    {_message, _status} = System.cmd("lttng", ["stop"])
    {view_msg, 0} = System.cmd("lttng", ["view"])
    # destroy_lttng_session()
    parse_results(view_msg)
  end

  def create_lttng_session(opts) do
    session_name = Keyword.get(opts, :session)
    {_message, _res} = System.cmd("lttng", ["create", session_name])
    :ok
  end

  def session_info(session_name) do
    {message, _res} = System.cmd("lttng", ["list", "-u", session_name])
    String.split(message, "\n")
  end

  def destroy_lttng_session() do
    System.cmd("lttng", ["destroy"])
  end

  def enable_events(opts) do
    tracepoint_map =
      erlang_tracepoints()
      |> Map.new(fn tp ->
        [domain, event] = String.split(tp, ":")
        {event, domain}
      end)

    Keyword.get(opts, :events)
    |> Enum.map(fn event ->
      domain = Map.get(tracepoint_map, "#{event}")

      if domain do
        {_message, _res} = System.cmd("lttng", ["enable-event", "-u", "#{domain}:#{event}"])
      else
        throw({:no_domain_for, event})
      end
    end)

    :ok
  end

  def start_lttng(_opts) do
    {_message, _res} = System.cmd("lttng", ["start"])
    :ok
  end

  def start_vm_tracing(opts) do
    start_trace(opts)
  end

  def start_trace(opts) do
    if :function_call in opts[:events] do
      start_trace(:function_call, opts[:patterns])
    else
      start_trace(:default, opts)
    end

    :ok
  end

  def start_trace(:function_call, patterns) do
    Enum.each(patterns, &dyntrace_mfa_pattern/1)
    :erlang.trace(:all, true, [:call, {:tracer, :dyntrace, []}])
  end

  def start_trace(:default, _opts) do
    # :erlang.trace(:new, true, [:procs, {:tracer, :dyntrace, []}])
    :ok
  end

  defp dyntrace_mfa_pattern(mfa) do
    :erlang.trace_pattern(mfa, [{:_, [], [{:return_trace}]}], [])
  end

  def parse_results(view_output) do
    String.split(view_output, "\n")
  end
end

defmodule LttngTest do
  use ExUnit.Case
  doctest Lttng

  test "greets the world" do
    assert Lttng.hello() == :world
  end
end
